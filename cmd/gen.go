package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdpDropTcp ../bpf/ebpf_program.c -- -I../bpf

