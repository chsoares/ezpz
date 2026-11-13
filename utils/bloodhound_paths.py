#!/usr/bin/env python3
"""Extract one-hop attack paths or attack chains from a BloodHound JSON zip.

Output is TSV:
  SOURCE<TAB>display<TAB>domain
  EDGE<TAB>target<TAB>target_type<TAB>target_dn<TAB>detail

Only the source principal's outgoing ACL edges and delegation properties are
returned. The caller is responsible for turning edges into commands.
"""

import argparse
import json
import sys
import zipfile
from pathlib import Path


def value(props, *names):
    for name in names:
        v = props.get(name)
        if v not in (None, "", []):
            return v
    return ""


def display_name(obj, typ=None):
    props = obj.get("Properties", {})
    sam = value(props, "samaccountname")
    name = sam or value(props, "name")
    if "@" in name:
        name = name.split("@", 1)[0]
    if typ == "User":
        return name.lower()
    if typ == "Group":
        return name.upper()
    if typ == "Computer":
        return name.upper()
    return name


def object_type(filename, obj):
    props = obj.get("Properties", {})
    classes = props.get("objectclass") or props.get("objectClass") or []
    if isinstance(classes, str):
        classes = classes.split(";")
    classes = {str(c).lower() for c in classes}

    low = filename.lower()
    if "users.json" in low or "user" in classes:
        return "User"
    if "groups.json" in low or "group" in classes:
        return "Group"
    if "computers.json" in low or "computer" in classes:
        return "Computer"
    if "domains.json" in low or "domain" in classes:
        return "Domain"
    if "ous.json" in low or "organizationalunit" in classes:
        return "OU"
    if "gpos.json" in low or "groupolicycontainer" in classes:
        return "GPO"
    return "Object"


def command_target(obj, typ):
    props = obj.get("Properties", {})
    if typ in ("User", "Group", "Computer"):
        sam = value(props, "samaccountname")
        if sam:
            if typ == "User":
                return sam.lower()
            if typ in ("Group", "Computer"):
                return sam.upper()
            return sam
    if typ == "Domain":
        return value(props, "name", "domain")
    return value(props, "distinguishedname", "name")


def target_fqdn(obj, typ):
    props = obj.get("Properties", {})
    if typ in ("Computer", "Domain"):
        return value(props, "name", "domain")
    return ""


def resolve_source(objects, source):
    needle = source.strip().lower()
    matches = []
    for obj in objects:
        props = obj.get("Properties", {})
        sid = obj.get("ObjectIdentifier", "")
        candidates = {
            sid.lower(),
            value(props, "samaccountname").lower(),
            value(props, "name").lower(),
            value(props, "distinguishedname").lower(),
        }
        name = value(props, "name")
        if "@" in name:
            candidates.add(name.split("@", 1)[0].lower())
        if needle in candidates and needle:
            matches.append(obj)
    if not matches:
        return None
    # Prefer a user object when the same name appears elsewhere.
    for obj in matches:
        if "users.json" in obj["_source"].lower():
            return obj
    return matches[0]


MEMBERSHIP_RIGHTS = {
    "AddSelf": 1,
    "AddMember": 1,
    "GenericAll": 2,
    "AllExtendedRights": 2,
    "WriteAllProperties": 2,
    "WriteDacl": 3,
    "WriteOwner": 3,
    "Owns": 3,
}


TAKEOVER_RIGHTS = {
    "ForceChangePassword": 1,
    "AddKeyCredentialLink": 1,
    "ReadLAPSPassword": 1,
    "ReadGMSAPassword": 1,
    "GenericAll": 2,
    "AllExtendedRights": 2,
    "GenericWrite": 2,
    "WriteAllProperties": 2,
    "WriteDacl": 3,
    "WriteOwner": 3,
    "Owns": 3,
    "DCSync": 1,
    "GetChangesAll": 1,
}


def object_by_sid(objects):
    return {o.get("ObjectIdentifier"): o for o in objects if o.get("ObjectIdentifier")}


def group_membership(objects):
    groups = {}
    for obj in objects:
        if object_type(obj["_source"], obj) == "Group":
            groups[obj.get("ObjectIdentifier", "")] = obj
    return groups


def identity_sids(sid, groups, cache):
    if sid in cache:
        return cache[sid]
    result = {sid}
    changed = True
    while changed:
        changed = False
        for group_sid, group in groups.items():
            if group_sid in result:
                continue
            if any(m.get("ObjectIdentifier") in result for m in (group.get("Members") or [])):
                result.add(group_sid)
                changed = True
    cache[sid] = result
    return result


def build_edges(objects):
    by_sid = object_by_sid(objects)
    edges = []
    for target_sid, obj in by_sid.items():
        target_type = object_type(obj["_source"], obj)
        if target_type not in ("User", "Computer", "Domain", "Group"):
            continue
        target = command_target(obj, target_type)
        target_dn = value(obj.get("Properties", {}), "distinguishedname")
        target_name = target_fqdn(obj, target_type)
        for ace in obj.get("Aces", []):
            right = value(ace, "RightName")
            if target_type == "Group":
                if right not in MEMBERSHIP_RIGHTS:
                    continue
                edge_cost = MEMBERSHIP_RIGHTS[right]
            else:
                if right not in TAKEOVER_RIGHTS:
                    continue
                edge_cost = TAKEOVER_RIGHTS[right]
            principal = ace.get("PrincipalSID")
            if not principal:
                continue
            edges.append({
                "principal": principal,
                "target": target_sid,
                "target_name": target,
                "target_type": target_type,
                "target_dn": target_dn,
                "target_fqdn": target_name,
                "right": right,
                "cost": edge_cost,
            })
    return by_sid, edges


def effective_sids(user_sid, extra_groups, groups, cache):
    sids = set(identity_sids(user_sid, groups, cache))
    for group_sid in extra_groups:
        sids.update(identity_sids(group_sid, groups, cache))
    return sids


def longest_chains(start_sid, edges, groups):
    """Return every unique longest fallback chain.

    Computer and domain endpoints are preferred over user endpoints. If no
    computer/domain chain exists, all tied user chains are returned.
    """
    cache = {}
    # Groups are intermediate objects; a useful fallback chain should end on a
    # principal that can actually be taken over (user, computer, or domain).
    useful_types = {"User", "Computer", "Domain"}

    start_sids = effective_sids(start_sid, (), groups, cache)
    direct_targets = {
        edge["target"]
        for edge in edges
        if edge["principal"] in start_sids and edge["target_type"] in useful_types
    }

    candidates = []
    best_len = 0

    def consider(state, path):
        nonlocal best_len
        if not path:
            return
        last_edge = path[-1][1]
        if last_edge["target_type"] not in useful_types:
            return
        # A longer detour to an object that is already reachable in one hop is
        # redundant; the direct edge is the best result for that endpoint.
        if last_edge["target"] in direct_targets and len(path) != 1:
            return
        if len(path) > best_len:
            best_len = len(path)
            candidates.clear()
        if len(path) == best_len:
            candidates.append((path[:], state))

    def visit(state, path, path_states, path_nodes):
        consider(state, path)
        user_sid, extra = state
        current_sids = effective_sids(user_sid, extra, groups, cache)
        for edge in edges:
            if edge["principal"] not in current_sids:
                continue
            next_sid = edge["target"]
            # A useful chain must advance through new objects; revisiting a
            # principal/group only creates noisy loops.
            if next_sid in path_nodes:
                continue
            if edge["target_type"] == "Group":
                if next_sid in current_sids:
                    continue
                next_state = (user_sid, tuple(sorted(set(extra) | {next_sid})))
            else:
                if next_sid == user_sid:
                    continue
                next_state = (next_sid, ())
            if next_state in path_states:
                continue
            visit(next_state, path + [(state, edge)], path_states | {next_state}, path_nodes | {next_sid})

    start_state = (start_sid, ())
    visit(start_state, [], {start_state}, {start_sid})
    if not candidates:
        return []

    # Prefer chains that end on a computer or domain; users are the fallback
    # only when there is no higher-value endpoint at the same depth.
    if any(steps[-1][1]["target_type"] in ("Computer", "Domain") for steps, _ in candidates):
        candidates = [
            item for item in candidates
            if item[0][-1][1]["target_type"] in ("Computer", "Domain")
        ]

    # The same object sequence can be reached through different ACEs; for a
    # summary/list view, the sequence itself is what matters.
    seen = set()
    unique = []
    for steps, state in candidates:
        key = tuple(edge["target"] for _, edge in steps)
        if key in seen:
            continue
        seen.add(key)
        unique.append((steps, state))

    unique.sort(key=lambda item: tuple(edge["target_name"].casefold() for _, edge in item[0]))
    return unique


def chain_output(source, target, objects, args, groups=None, by_sid=None, edges=None, target_obj=None):
    if groups is None:
        groups = group_membership(objects)
    if by_sid is None or edges is None:
        by_sid, edges = build_edges(objects)

    source_sid = source.get("ObjectIdentifier", "")
    source_type = object_type(source["_source"], source)
    source_name = display_name(source, source_type)
    source_props = source.get("Properties", {})
    source_domain = value(source_props, "domain", "domainsid")

    if target:
        if target_obj is None:
            target_obj = resolve_source(objects, target)
        if not target_obj:
            print(f"Target not found in BloodHound data: {target}", file=sys.stderr)
            return 1
    else:
        target_obj = None
        for obj in objects:
            if object_type(obj["_source"], obj) != "Domain":
                continue
            props = obj.get("Properties", {})
            if source_domain and value(props, "name", "domain").lower() == source_domain.lower():
                target_obj = obj
                break
        if target_obj is None:
            for obj in objects:
                if object_type(obj["_source"], obj) == "Domain":
                    target_obj = obj
                    break
        if target_obj is None:
            print("No domain object found in BloodHound data.", file=sys.stderr)
            return 1

    target_sid = target_obj.get("ObjectIdentifier", "")
    target_type = object_type(target_obj["_source"], target_obj)
    target_name = command_target(target_obj, target_type)

    import heapq
    inf = 10**9
    start_state = (source_sid, ())
    dist = {start_state: 0}
    prev = {}
    heap = [(0, start_state)]
    found_state = None
    cache = {}

    while heap:
        cost, state = heapq.heappop(heap)
        if cost != dist.get(state):
            continue
        user_sid, extra = state
        sids = effective_sids(user_sid, extra, groups, cache)
        if user_sid == target_sid:
            found_state = state
            break
        if target_type == "Group" and target_sid in sids:
            found_state = state
            break
        for edge in edges:
            if edge["principal"] not in sids:
                continue
            if edge["target_type"] == "Group":
                if edge["target"] in sids:
                    continue
                next_state = (user_sid, tuple(sorted(set(extra) | {edge["target"]})))
            else:
                if edge["target"] == user_sid:
                    continue
                next_state = (edge["target"], ())
            next_cost = cost + edge["cost"]
            if next_cost < dist.get(next_state, inf):
                dist[next_state] = next_cost
                prev[next_state] = (state, edge)
                heapq.heappush(heap, (next_cost, next_state))

    chains = []
    if found_state is None:
        if not args.fallback_longest:
            if args.batch:
                return 0
            print(f"No chain found from {source_name} to {target_name}.", file=sys.stderr)
            return 1

        candidates = longest_chains(source_sid, edges, groups)
        if not candidates:
            if args.batch:
                return 0
            print(f"No chain found from {source_name} to {target_name}.", file=sys.stderr)
            return 1
        if not args.batch:
            plural = "chains" if len(candidates) > 1 else "chain"
            print(f"FALLBACK\tNo chain found from {source_name} to {target_name}.\tFalling back to longest reachable {plural}.")

        for steps, _ in candidates:
            endpoint_sid = steps[-1][1]["target"]
            endpoint_obj = by_sid.get(endpoint_sid)
            if not endpoint_obj:
                continue
            endpoint_type = object_type(endpoint_obj["_source"], endpoint_obj)
            endpoint_name = command_target(endpoint_obj, endpoint_type)
            chains.append((endpoint_name, endpoint_type, steps))
    else:
        steps = []
        current = found_state
        while current != start_state:
            previous, edge = prev[current]
            steps.append((previous, edge))
            current = previous
        steps.reverse()
        chains.append((target_name, target_type, steps))

    if not chains:
        if args.batch:
            return 0
        print(f"No chain found from {source_name} to {target_name}.", file=sys.stderr)
        return 1

    if args.batch:
        print(f"USER\t{source_name}\t{source_domain}")

    for chain_index, (chain_target, chain_target_type, steps) in enumerate(chains, 1):
        print(f"CHAIN\t{chain_index}")
        print(f"SOURCE\t{source_name}\t{source_domain}")
        print(f"TARGET\t{chain_target}\t{chain_target_type}")
        for index, (_previous_state, edge) in enumerate(steps, 1):
            principal_obj = by_sid.get(edge["principal"])
            principal_type = object_type(principal_obj["_source"], principal_obj) if principal_obj else ""
            source_name_step = display_name(principal_obj, principal_type) if principal_obj else edge["principal"]
            fields = [
                str(index),
                edge["right"],
                source_name_step,
                edge["target_name"],
                edge["target_type"],
                edge["target_dn"],
                edge["target_fqdn"],
            ]
            print("STEP\t" + "\t".join(str(x).replace("\t", " ") for x in fields))
    return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True)
    parser.add_argument("--from", dest="source", default="")
    parser.add_argument("--from-file", dest="source_file", default="")
    parser.add_argument("--chain", action="store_true")
    parser.add_argument("--to", default="")
    parser.add_argument("--fallback-longest", action="store_true")
    parser.add_argument("--batch", action="store_true")
    args = parser.parse_args()

    try:
        zf = zipfile.ZipFile(args.zip)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"Invalid BloodHound zip: {exc}", file=sys.stderr)
        return 1

    objects = []
    with zf:
        for info in zf.infolist():
            if not info.filename.lower().endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(info.filename))
            except (ValueError, KeyError):
                continue
            payload = data.get("data", [])
            if not isinstance(payload, list):
                continue
            for obj in payload:
                if isinstance(obj, dict) and obj.get("ObjectIdentifier"):
                    obj["_source"] = info.filename
                    objects.append(obj)

    if args.source_file:
        if not args.chain:
            print("--from-file is only supported with --chain.", file=sys.stderr)
            return 1
        try:
            with open(args.source_file, encoding="utf-8") as handle:
                users = [
                    line.strip() for line in handle
                    if line.strip() and not line.lstrip().startswith("#")
                ]
        except OSError as exc:
            print(f"Cannot read user list: {exc}", file=sys.stderr)
            return 1
        users = list(dict.fromkeys(users))
        args.batch = True
        groups = group_membership(objects)
        by_sid, edges = build_edges(objects)
        target_obj = None
        if args.to:
            target_obj = resolve_source(objects, args.to)
            if not target_obj:
                print(f"Target not found in BloodHound data: {args.to}", file=sys.stderr)
                return 1
        for user in users:
            source = resolve_source(objects, user)
            if not source:
                continue
            status = chain_output(
                source, args.to, objects, args,
                groups=groups, by_sid=by_sid, edges=edges, target_obj=target_obj,
            )
            if status != 0:
                return status
        return 0

    if not args.source:
        print("Either --from or --from-file is required.", file=sys.stderr)
        return 1

    source = resolve_source(objects, args.source)
    if not source:
        print(f"Principal not found in BloodHound data: {args.source}", file=sys.stderr)
        return 1

    if args.chain:
        return chain_output(source, args.to, objects, args)

    source_sid = source.get("ObjectIdentifier", "")
    source_props = source.get("Properties", {})
    source_name = display_name(source, object_type(source["_source"], source))
    source_domain = value(source_props, "domain", "domainsid")
    print(f"SOURCE\t{source_name}\t{source_domain}")

    # BloodHound puts group-derived rights on the group ACE, so include the
    # source's transitive group memberships when matching principals.
    groups = {}
    for obj in objects:
        if object_type(obj["_source"], obj) == "Group":
            groups[obj.get("ObjectIdentifier", "")] = obj

    source_sids = {source_sid}
    group_names = {source_sid: source_name}
    changed = True
    while changed:
        changed = False
        for sid, group in groups.items():
            if sid in source_sids:
                continue
            members = group.get("Members") or []
            if any(m.get("ObjectIdentifier") in source_sids for m in members):
                source_sids.add(sid)
                group_names[sid] = display_name(group, "Group")
                changed = True

    seen = set()

    def emit(edge, target, target_type, target_dn="", target_name="", detail=""):
        key = (edge, target, target_type, target_dn, target_name, detail)
        if key in seen:
            return
        seen.add(key)
        fields = [edge, target, target_type, target_dn, target_name, detail]
        print("\t".join(str(x).replace("\t", " ") for x in fields))

    for obj in objects:
        target_type = object_type(obj["_source"], obj)
        target = command_target(obj, target_type)
        target_dn = value(obj.get("Properties", {}), "distinguishedname")
        target_name = target_fqdn(obj, target_type)

        for ace in obj.get("Aces", []):
            principal = ace.get("PrincipalSID")
            if principal not in source_sids:
                continue
            right = value(ace, "RightName")
            if right:
                via = "" if principal == source_sid else f"via {group_names.get(principal, principal)}"
                emit(right, target, target_type, target_dn, target_name, via)

        # Realm configuration for RBCD is stored on the target computer.
        if any(sid in (obj.get("AllowedToAct") or []) for sid in source_sids):
            emit("AllowedToAct", target, target_type, target_dn, target_name)

    # Constrained delegation is a property of the source object.
    for spn in source_props.get("allowedtodelegate") or []:
        emit("AllowedToDelegate", spn, "SPN", spn, spn)

    return 0


if __name__ == "__main__":
    sys.exit(main())
