# protocols-watch — Architecture

## Flujo

```
/proc/net/protocols  ──► parse_protocols_file()  ──► std::vector<Proto>
                                  │
                                  ▼
                     classify_family() + decode_ops()
                                  │
                        stable_sort (sockets desc, name)
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             render_snapshot()            render_json()
                    │
     filtros (active/family/name/press/slab/top) → watch delta
```

## Decisiones técnicas

- **Monolítico stdlib-only**: un solo TU, `g++ -std=c++23` directo, zero
  dependencias (`<charconv>` para parseo, `<algorithm>` para sort).
- **Formato kernel**: `proto_seq_show()` imprime 8 campos fijos + 18 flags
  `y/n` de `proto_method_implemented`. El parser exige ≥8 tokens y recorta
  las flags a 18 caracteres.
- **`memory = -1` / `press = NI`**: el protocolo no registra contador de
  memoria (PACKET, UNIX, NETLINK…). No es un error de parseo.
- **Dumps tolerantes**: `--file` salta comentarios `#`, líneas vacías,
  cabecera (`protocol`) y filas malformadas.
- **Paleta ANSI mutable**: `--no-color` vacía las strings de color en runtime
  (no `constexpr`) — afecta por igual a selftest, watch y snapshot.
- **Watch flush**: `render_delta()` termina con `std::cout << std::flush` para
  que `timeout 4 ./protocols-watch --watch 1 > log` nunca pierda frames.
- **JSON a mano**: claves siempre entre comillas; `json_escape` para nombres.
