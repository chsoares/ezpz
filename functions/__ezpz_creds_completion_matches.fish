function __ezpz_creds_completion_matches --argument-names domain filter
    test -n "$filter"; or return 0
    if test "$filter" = local
        test "$domain" = local; or string match -q 'local.*' -- $domain
    else if string match -q 'local.*' -- $filter
        test "$domain" = "$filter"
    else
        test "$domain" = "$filter"; or test -z "$domain"
    end
end
