package sandbox

import goruntime "runtime"

var isLinux = goruntime.GOOS == "linux"
