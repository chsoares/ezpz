#!/usr/bin/env python3
"""Extract one-hop attack paths from a BloodHound JSON zip.

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


def display_name(obj):
    props = obj.get("Properties", {})
    sam = value(props, "samaccountname")
    if sam:
        return sam
    name = value(props, "name")
    if "@" in name:
        name = name.split("@", 1)[0]
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
        if target_type not in ("User", "Computer", "Domain"):
            continue
        target = command_target(obj, target_type)
        target_dn = value(obj.get("Properties", {}), "distinguishedname")
        target_name = target_fqdn(obj, target_type)
        for ace in obj.get("Aces", []):
            right = value(ace, "RightName")
            if right not in TAKEOVER_RIGHTS:
                continue
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
                "cost": TAKEOVER_RIGHTS[right],
            })
    return by_sid, edges


def longest_chain(start_sid, edges, groups):
    best = []

    def visit(sid, path, path_sids):
        nonlocal best
        if len(path) > len(best):
            best = path[:]
        current_sids = identity_sids(sid, groups, {})
        for edge in edges:
            if edge["principal"] not in current_sids:
                continue
            next_sid = edge["target"]
            if next_sid in path_sids:
                continue
            visit(next_sid, path + [(sid, edge)], path_sids | {next_sid})

    visit(start_sid, [], {start_sid})
    return best


def chain_output(source, target, objects, args):
    groups = group_membership(objects)
    source_sid = source.get("ObjectIdentifier", "")
    source_name = display_name(source)
    source_props = source.get("Properties", {})
    source_domain = value(source_props, "domain", "domainsid")
    by_sid, edges = build_edges(objects)

    if target:
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
    dist = {source_sid: 0}
    prev = {}
    heap = [(0, source_sid)]
    cache = {}

    while heap:
        cost, current = heapq.heappop(heap)
        if cost != dist.get(current):
            continue
        current_sids = identity_sids(current, groups, cache)
        for edge in edges:
            if edge["principal"] not in current_sids:
                continue
            next_sid = edge["target"]
            next_cost = cost + edge["cost"]
            if next_cost < dist.get(next_sid, inf):
                dist[next_sid] = next_cost
                prev[next_sid] = (current, edge)
                heapq.heappush(heap, (next_cost, next_sid))

    if target_sid not in prev and target_sid != source_sid:
        if args.fallback_longest:
            original_target_name = target_name
            steps = longest_chain(source_sid, edges, groups)
            if not steps:
                print(f"No chain found from {source_name} to {target_name}.", file=sys.stderr)
                return 1
            print(f"FALLBACK\tNo chain found from {source_name} to {original_target_name}.\tFalling back to longest reachable chain.")
            target_sid = steps[-1][1]["target"]
            target_obj = by_sid.get(target_sid)
            target_type = object_type(target_obj["_source"], target_obj)
            target_name = command_target(target_obj, target_type)
        else:
            print(f"No chain found from {source_name} to {target_name}.", file=sys.stderr)
            return 1
    else:
        steps = []
        current = target_sid
        while current != source_sid:
            previous, edge = prev[current]
            steps.append((previous, edge))
            current = previous
        steps.reverse()

    print(f"SOURCE\t{source_name}\t{source_domain}")
    print(f"TARGET\t{target_name}\t{target_type}")
    for index, (previous, edge) in enumerate(steps, 1):
        source_name_step = display_name(by_sid.get(previous, {}))
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
    parser.add_argument("--from", dest="source", required=True)
    parser.add_argument("--chain", action="store_true")
    parser.add_argument("--to", default="")
    parser.add_argument("--fallback-longest", action="store_true")
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

    source = resolve_source(objects, args.source)
    if not source:
        print(f"Principal not found in BloodHound data: {args.source}", file=sys.stderr)
        return 1

    if args.chain:
        return chain_output(source, args.to, objects, args)

    source_sid = source.get("ObjectIdentifier", "")
    source_props = source.get("Properties", {})
    source_name = display_name(source)
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
                group_names[sid] = display_name(group)
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
