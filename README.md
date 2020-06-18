# SRB2 Query

Python implementation of [SRB2 Query](https://git.magicalgirl.moe/james/SRB2-Query)

Can be used to request info from an SRB2 server

## Usage

```
q = SRB2Query("localhost")
server, player = q.askinfo()
print(server.__dict__)
print(player.__dict__)
```

Then the `server` and `player` packets can be read to obtain the info from the server.

## Feature

Currently does not interpret every field, feel free to fork and PR!
