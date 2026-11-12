function __ezpz_creds_completion_domain
    set -l tokens (commandline -opc)
    set -l want 0
    for token in $tokens
        if test $want -eq 1
            echo $token
            return
        end
        if test "$token" = "-d"; or test "$token" = "--domain"
            set want 1
        else if string match -q -- '--domain=*' $token
            string replace -- '--domain=' '' $token
            return
        end
    end
end
