_oktaws() {
    local i cur prev opts cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}
    do
        case "${i}" in
            oktaws)
                cmd="oktaws"
                ;;
            
            *)
                ;;
        esac
    done

    case "${cmd}" in
        oktaws)
            opts=" -f -v -h -V -o -r -u  --force-new --verbose --help --version --organization --role --username --profiles  <profile> "
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                return 0
            fi
            case "${prev}" in
                
                --organization)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                    -o)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                --role)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                    -r)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                --username)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                    -u)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                --profiles)
                    COMPREPLY=($(compgen -f ${cur}))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
        
    esac
}

complete -F _oktaws -o bashdefault -o default oktaws
