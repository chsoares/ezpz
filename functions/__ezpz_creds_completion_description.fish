function __ezpz_creds_completion_description --argument-names domain
    if test "$domain" = local
        echo local
    else if string match -q 'local.*' -- $domain
        string replace -- 'local.' '' $domain
    else if test -z "$domain"
        echo "(no domain)"
    else
        echo $domain
    end
end
