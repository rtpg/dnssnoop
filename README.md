# dnssnoop

`dnssnoop` logs DNS resolution requests made by applications, along with the latency in making these DNS resolutions.

Currently this can capture requests made to `libc` (`getaddrinfo`, `gethostbyname` and friends). Requests made by programs sidestepping `libc` entirely will not be seen.

This can be used to audit what sort of domains your programs are reaching out to. By combining it 

## DNS Schema

|Field|Type|Description|
------------------------
| `pid`         | `int`    | The process ID |
| `name`        | `string` |          Foo      |
| `lib_func`    | `string` | The library function called to do the resolution(for example `gethostbyname`) |
| `duration_ns` | `long`   | The duration of the function call (in nanoseconds) |



## Query Example

Seeing what events are being called, assuming you have also added `execsnoop`.

This query assumes you put `dnssnoop` data into `dns_call` and `execsnoop` data into the `execsnoop` table

``` sql
with dns_data as (
    select 
     event->>'$.pid' as pid,
     event->>'$.cmd' as dns_query
    from dns_call 
), exec_data as (

    select 
        event->> '$.pid' as pid,
        event->> '$.comm' as comm
    from execsnoop)
select 
  exec_data.pid,
  exec_data.comm,
  dns_query
from dns_data join exec_data on dns_data.pid = exec_data.pid
```
