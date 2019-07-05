# oci-trace-hook
OCI hook for tracing syscalls and generating a SECCOMP profile for a container

Can only be run as root or with `CAP_SYS_ADMIN`

## Dependencies
- bcc
- gobpf

## Build
-`go build`
- copy the binary to `/usr/libexec/oci/hook.d/`
-`sudo podman run [FLAGS] --annotation seccomp=true [IMAGE] [COMMAND]`
