#!/bin/bash

set -e

langs="python"

binary="$1"
output="$2"

dir="$(dirname "$0")"
tmpdir="$(mktemp --directory --tmpdir "make_dropper.XXXXXXXXXX")"

cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT

compile_loader() {
    gcc -ffreestanding -nostdlib \
        -static-pie -Wl,--oformat=binary \
        -Os -fno-asynchronous-unwind-tables -flto \
        -o "${tmpdir}/loader.bin" "${dir}/loader.c" -lgcc \
        "$@"
}

exec {other_stdout}>&1
{ IFS= read -r loader_start_addr; } < <(
    exec {output_loader_addr}>&1
    # echo deadbeef >&${output_loader_addr}
    compile_loader -Wl,-Map=>(
        sed --regexp-extended --silent \
            --expression='s/^.*\b0x([0-9a-f]+)\s+_start$/\1/;T;p' \
            >&${output_loader_addr}
    ) >&${other_stdout}
    exec {output_loader_addr}>&-
)
exec {other_stdout}>&-

write_script() {
    cat <<EOSCRIPT

set -e

get_trampoline() {
    echo '$(python "${dir}/compress.py" "${tmpdir}/loader.bin")'
}

EOSCRIPT

    for lang in $langs; do (
        . "${dir}/${lang}/lang.conf"

        cat <<EOSCRIPT
try_${lang}() {
    command -v "\$1" >/dev/null 2>&1 || return
    { echo '$(python "${dir}/compress.py" "${dir}/${lang}/${test_script}")' | "\$1" ${run_script_from_fd_cmd} 0; } || return
    set -- \$("\$1" ${get_free_fds_cmd}) \\
        '$(echo "${loader_start_addr}")' \\
        "\$0" "\$@"
    eval "exec \$1<&1" 1<&0
    {
        echo '$(python "${dir}/compress.py" "${dir}/${lang}/${load_script}")'
        get_trampoline
        set +e
    } | {
        eval "exec \$2<&1" 1<&0
        exec <&\$1
        eval "exec \$1<&-"
        shift
        exec "\$4" ${run_script_from_fd_cmd} "\$@"
    }
    exit $?
}
EOSCRIPT
    ); done

    cat <<EOSCRIPT
main() {
$(for lang in $langs; do (
      . "${dir}/${lang}/lang.conf"
      for impl in "${impls[@]}"; do
          cat <<EOSCRIPT2
    try_${lang} "${impl}" "\$@"
EOSCRIPT2
      done)
  done)
}

main "\$@"
echo "Failed!"
exit 1

EOSCRIPT
}

write_output_file() {
    header_str="CECFHDR@"
    script_len=$({ echo $header_str; write_script; } | wc -c)
    num_len_chars=1
    while true; do
        offset=$((script_len + num_len_chars))
        if (( $(echo -n $offset | wc -c) <= num_len_chars )); then
            break;
        fi
        (( ++num_len_chars ))
    done

    printf '\n\n# %s%-*s\n' "$header_str" "$num_len_chars" "$offset"
    write_script
    python "${dir}/mkheader.py" "${binary}"
    cat "${binary}"
}

if [[ $output && $output != "-" ]]; then
    write_output_file >"${tmpdir}/script.sh"
    mv "${tmpdir}/script.sh" "${output}"
else
    write_output_file
fi
