# # special symbols

# function ezpz_header
#     echo (set_color yellow --bold)"  "$argv(set_color normal)
# end
# function ezpz_info
#     echo (set_color cyan)"  "$argv(set_color normal)
# end
# function ezpz_cmd
#     echo (set_color blue)"  "$argv(set_color normal)
# end
# function ezpz_error
#     echo (set_color red --bold)"  "$argv(set_color normal)
# end
# function ezpz_warn
#     echo (set_color magenta --bold)"  "$argv(set_color normal)
# end
# function ezpz_success
#     echo (set_color magenta --bold)"  "$argv(set_color normal)
# end
# function ezpz_question
#     echo (set_color blue)"  "$argv(set_color normal)
# end
# function ezpz_title
#     echo (set_color magenta --bold)"  "$argv(set_color normal)
# end


# no special symbols

function ezpz_header
    echo (set_color yellow --bold)"[+] "$argv(set_color normal)
end
function ezpz_info
    echo (set_color cyan)"[*] "$argv(set_color normal)
end
function ezpz_cmd
    echo (set_color blue)"[>] "$argv(set_color normal)
end
function ezpz_error
    echo (set_color red --bold)"[!] "$argv(set_color normal)
end
function ezpz_warn
    echo (set_color red)"[-] "$argv(set_color normal)
end
function ezpz_success
    echo (set_color magenta --bold)"[✓] "$argv(set_color normal)
end
function ezpz_question
    echo (set_color blue)"[?] "$argv(set_color normal)
end
function ezpz_title
    echo (set_color magenta --bold)"[~] "$argv(set_color normal)
end