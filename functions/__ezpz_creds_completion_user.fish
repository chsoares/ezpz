function __ezpz_creds_completion_user
    set -l tokens (commandline -opc)
    set -l want 0
    for token in $tokens
        if test $want -eq 1
            set -l user $token
            if string match -q '*@*' -- $user
                set user (string split -m1 '@' -- $user)[1]
            else if string match -rq '\\\\' -- $user
                set user (string split -m1 '\\' -- $user)[2]
            end
            echo $user
            return
        end
        if test "$token" = "-u"; or test "$token" = "--user"
            set want 1
        else if string match -q -- '--user=*' $token
            set -l user (string replace -- '--user=' '' $token)
            if string match -q '*@*' -- $user
                set user (string split -m1 '@' -- $user)[1]
            else if string match -rq '\\\\' -- $user
                set user (string split -m1 '\\' -- $user)[2]
            end
            echo $user
            return
        end
    end
end
