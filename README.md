# protocols-watch

Monitor de la tabla de protocolos de socket del kernel Linux en tiempo
real (C++23, zero deps).

Lee `/proc/net/protocols` (exportado por `proto_seq_show` en `net/core/sock.c`)
y muestra cada protocolo registrado: tamaño del objeto, sockets en uso,
memoria asignada, indicador de presión de memoria, `max_header`, si usa slab,
módulo propietario y las 18 flags de `proto_ops` (`cl` close, `co` connect,
`di` disconnect, `ac` accept, `io` ioctl, `in` init, `de` destroy, `sh`
shutdown, `ss` setsockopt, `gs` getsockopt, `se` sendmsg, `re` recvmsg,
`bi` bind, `br` backlog_rcv, `ha` hash, `uh` unhash, `gp` get_port, `em`
enter_memory_pressure). Clasifica la familia (`ipv4`, `ipv6`, `unix`,
`netlink`, `packet`, `xdp`, `mctp`). Útil para ver qué stacks tienen
sockets vivos, detectar presión de memoria en TCP y auditar protocolos
poco habituales (XDP, MCTP, MPTCP).

## Features

- **Fuente única**: `/proc/net/protocols` (tabla completa del kernel)
- **Familias simbólicas**: `ipv4` / `ipv6` / `unix` / `netlink` / `packet` / `xdp` / `mctp`
- **Flags proto_ops**: 18 columnas `y/n` decodificadas con `--ops` (`cl|co|di|...`)
- **Presión de memoria**: `NI` (sin indicador), `no`, `yes` (TCP bajo presión en rojo)
- **Modo watch (`--watch N`)**: refresh periódico con deltas (nuevos/cerrados/crecieron/decrecieron) y flush por frame
- **Salida JSON (`--json`)**: `summary` + array `protocols` validable con `python -m json.tool`
- **Demo mode (`--demo`)**: host sintético ocupado con 18 protocolos (208 sockets)
- **Filtros**: `--active`, `--family NAME`, `--name PREFIX`, `--press`, `--slab`, `--top N`
- **`--file`**: parsea un dump (tolera comentarios `#`)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 74 checks (clasificador, ops, parser, filtros, demo, JSON, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o protocols-watch
```

## Usage

```bash
# Snapshot único (host real)
./protocols-watch

# Solo protocolos con sockets vivos
./protocols-watch --active

# Solo IPv6
./protocols-watch --family ipv6

# Prefijo de nombre (UDP, UDP-Lite, UDPv6, UDPLITEv6)
./protocols-watch --name UDP

# Bajo presión de memoria
./protocols-watch --press

# Flags proto_ops decodificadas
./protocols-watch --ops --active

# Modo watch (cada 2s) con deltas
./protocols-watch --watch 2

# JSON
./protocols-watch --json

# Demo (host sintético)
./protocols-watch --demo

# Parsear un dump con comentarios
./protocols-watch --file sample-protocols.table --no-color

# Sin colores
./protocols-watch --no-color

# Auto-tests
./protocols-watch --selftest
```

## Data Source

`/proc/net/protocols` — tabla de `struct proto` del kernel:

```
protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re bi br ha uh gp em
TCP       2304     22       0   no     320   yes  kernel      y  y  y  y  y  y  y  y  y  y  y  y  n  y  y  y  y  y
PACKET    1536      0      -1   NI       0   no   kernel      n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n  n
```

`memory = -1` y `press = NI` significan que el protocolo no registra contador
de memoria. Las 18 columnas finales son `proto_method_implemented()`.

## License

MIT
