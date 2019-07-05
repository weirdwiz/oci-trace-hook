package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	bpf "github.com/iovisor/gobpf/bcc"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	seccomp "github.com/seccomp/libseccomp-golang"
)

type event struct {
	Pid uint32
	ID  uint32
	// Inum    uint
	Command [16]byte
}

type calls map[string]int

const source string = `
#include <linux/bpf.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>

BPF_HASH(parent_namespace, u64, unsigned int);
BPF_PERF_OUTPUT(events);

struct data_t
{
    u32 pid;
    u32 id;
    char comm[16];
};

int enter_trace(struct tracepoint__raw_syscalls__sys_enter *args)
{
    struct data_t data = {};
    u64 key = 0;
    unsigned int zero = 0;
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid();
    data.id = (int)args->id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *ns = task->nsproxy;
    unsigned int inum = ns->pid_ns_for_children->ns.inum;

    if (data.pid == PARENT_PID)
    {
        parent_namespace.update(&key, &inum);
    }
    unsigned int *parent_inum = parent_namespace.lookup_or_init(&key, &zero);

    if (*parent_inum != inum)
    {
        return 0;
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
`

func main() {
	logfile, err := os.OpenFile(os.TempDir()+"/logfile", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	log.SetOutput(logfile)
	log.Println(os.Args)
	terminate := flag.Bool("e", false, "send SIGINT to floating process")
	runBPF := flag.Int("r", 0, "-r <pid of the container>")
	flag.Parse()

	if *runBPF > 0 {
		syscalls := make(calls, 303)
		pid := *runBPF
		src := strings.Replace(source, "PARENT_PID", strconv.Itoa(pid), -1)
		m := bpf.NewModule(src, []string{})
		defer m.Close()

		tracepoint, err := m.LoadTracepoint("enter_trace")
		if err != nil {
			log.Println(err)
		}

		if err := m.AttachTracepoint("raw_syscalls:sys_enter", tracepoint); err != nil {
			log.Println("unable to load tracepoint")
		}

		log.Println("tracepoint attached")

		table := bpf.NewTable(m.TableId("events"), m)
		channel := make(chan []byte)
		perfMap, err := bpf.InitPerfMap(table, channel)
		if err != nil {
			log.Println("unable to init perf map")
		}

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, os.Kill)
		rsc := false
		go func() {
			var e event
			for {
				data := <-channel
				err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
				if err != nil {
					log.Printf("failed to decode received data '%s': %s\n", data, err)
					continue
				}
				// comm := (*C.char)(unsafe.Pointer(&e.Command))
				// log.Printf("Pid : %d, Syscall_ID : %d, , Command : %q", e.Pid, e.Id, C.GoString(comm))
				name := getName(e.ID)
				if name == "seccomp" {
					rsc = true
					continue
				}
				if rsc {
					syscalls[name]++
				}
			}
		}()
		log.Println("PerfMap Start")
		perfMap.Start()
		<-sig
		log.Println("PerfMap Stop")
		perfMap.Stop()
		generateProfile(syscalls, os.TempDir()+"/profile.json")
	} else if *terminate {
		log.Println("terminator")
		f, err := ioutil.ReadFile("pid")

		if err != nil {
			log.Println(err)
		}

		log.Println("file opened")
		Spid := string(f)

		log.Println(Spid)
		pid, _ := strconv.Atoi(Spid)
		p, _ := os.FindProcess(pid)
		p.Signal(os.Interrupt)

	} else {
		var s spec.State
		reader := bufio.NewReader(os.Stdin)
		decoder := json.NewDecoder(reader)
		err := decoder.Decode(&s)
		if err != nil {
			log.Println(err)
		}
		pid := s.Pid
		//sysproc := &syscall.SysProcAttr{Noctty: true}
		attr := &os.ProcAttr{
			Dir: ".",
			Env: os.Environ(),
			Files: []*os.File{
				os.Stdin,
				nil,
				nil,
			},
			// Sys: sysproc,
		}
		if pid > 0 {
			process, err := os.StartProcess("/usr/libexec/oci/hooks.d/trace", []string{"/usr/libexec/oci/hooks.d/trace", "-r", strconv.Itoa(pid)}, attr)
			if err != nil {
				log.Println("cannot launch process ", err.Error())
				return
			}
			time.Sleep(2 * time.Second)
			processPID := process.Pid
			pwd, _ := os.Getwd()
			log.Println("Currently in the directory ", pwd)
			f, err := os.Create("pid")
			if err != nil {
				log.Println("Cannot write pid to file")
			}
			defer f.Close()
			f.WriteString(strconv.Itoa(processPID))
			err = process.Release()
			if err != nil {
				log.Println("cannot detach process", err.Error())
			}
			log.Println("PID of the process : ", processPID)
		}
	}

}

func generateProfile(c calls, fileName string) {
	s := types.Seccomp{}
	var names []string
	for s, t := range c {
		if t > 0 {
			names = append(names, s)
		}
	}
	s.DefaultAction = types.ActErrno

	s.Syscalls = []*types.Syscall{
		&types.Syscall{
			Action: types.ActAllow,
			Names:  names,
			Args:   []*types.Arg{},
		},
	}
	sJSON, _ := json.Marshal(s)

	err := ioutil.WriteFile(fileName, sJSON, 0644)
	if err != nil {
		panic(err)
	}
}

func getName(id uint32) string {
	name, _ := seccomp.ScmpSyscall(id).GetName()
	return name
}
