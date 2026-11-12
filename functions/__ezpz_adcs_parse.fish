# Parse the text output of nxc's certipy-find module into stable records:
#   CANAME|<name>
#   CADNS|<dns name>
#   ESC|<esc>|<CA|Template>|<object>|<description>
function __ezpz_adcs_parse
    grep -a 'CERTIPY-' \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
        | awk '
        function trim(s) {
            gsub(/^[ \t]+|[ \t]+$/, "", s)
            return s
        }
        /^[ \t]*Certificate Authorities[ \t]*$/ { section = "CA"; next }
        /^[ \t]*Certificate Templates[ \t]*$/ { section = "Template"; next }
        /^[ \t]*CA Name[ \t]*:/ {
            section = "CA"
            name = trim(substr($0, index($0, ":") + 1))
            print "CANAME|" name
            next
        }
        /^[ \t]*DNS Name[ \t]*:/ {
            if (section == "CA") {
                print "CADNS|" trim(substr($0, index($0, ":") + 1))
            }
            next
        }
        /^[ \t]*Template Name[ \t]*:/ {
            section = "Template"
            name = trim(substr($0, index($0, ":") + 1))
            next
        }
        /^[ \t]*ESC[0-9]+[ \t]*:/ {
            line = $0
            sub(/^[ \t]+/, "", line)
            pos = index(line, ":")
            esc = trim(substr(line, 1, pos - 1))
            desc = trim(substr(line, pos + 1))
            gsub(/\|/, "/", desc)
            if (section == "" || name == "") next
            key = section SUBSEP name SUBSEP esc
            if (!(key in seen)) {
                seen[key] = 1
                print "ESC|" esc "|" section "|" name "|" desc
            }
        }'
end
