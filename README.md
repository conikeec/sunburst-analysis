# Building blocks of NGSAST Policy for sunburst backdoor detection



### Create the Code Property Graph
```
// Derived from https://github.com/Shadow0ps/solorigate_sample_source/
val sunburst_cpg = importCpg(“/XXX/sunburst.bin.zip")
```
### Fetch all hardcoded literals in the trojanized DLL . The system needs to set a threshold to determine if there are one too many hashed literals in the list. To determine the encoding scheme follow the method that is dereferencing each literal to attempt a reversal (the scheme could be base64 encode, SHA-x, FNV-1a). In cases like these, attempt to brute force the decoding process by running this analysis in a separate thread (could be computationally intensive). Skipping the decoding process as FNV-1a was determined to be the encoding scheme (by FireEye and adjunct community) in the GetHash(..) function
```
val all_literals = cpg.literal.code.l.distinct.map(_.replaceAll("^\"|\"$", "")).toSet
```

#### result>
```
"80zT9cvPS9X1TSxJzgAA",
"1970",
"300000UL",
"UyotTi3yTFGyUqo2qFXSAQA=",
"UypOLS7OzM/zTFGyUqo2qFXSAQA=",
"UyouSS0oVrKKBgA=",
"512",
"2UL",
"18446744073709551613UL",
"UwrJzE0tLknMLVCyUorRd0ksSdWoNqjVjNFX0gEA",
"U/LMS0mtULKqNqjVAQA=",
"U3ItS80rCaksSFWyUvIvyszPU9IBAA==",
"U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==",
"U3IpLUosyczP8y1Wsqo2qNUBAA==",
"UwouTU5OTU1JTVGyKikqTdUBAA==",
"U/JNLS5OTE9VslKqNqhVAgA=",
….
```

### There are many encoded literals in the code .. Let's attempt a base64 decode to detect literals. Other than keeping hardcoded values in hashed form, the malware has used DEFLATE compression to keep strings like WMI queries, registry entries and tokens.
```
decodeBase64()
```

### For keeping the hardcoded values in the file like the list of processes, services, etc., the malware used a variant of the FNV-1a hashing algorithm by XORing the computed hash of the string with a hardcoded value at the end. In order to determine functions using Hashing techniques, ideintiy all code blocks using AND, XOR .. operators

```
cpg.method.name("<operator>.(and|xor|or)").caller.fullName.l.distinct
```

### Identify all methods that take literals (hardcoded) as arguments

```
cpg.call.name(Operators.equals).where(_.argument.order(2).isLiteral).code.l
```

### Spawning threads as a background task could be both benign and suspicious at the same time, especially if the instance spawned is dealing with obfuscated hashes

```
val all_methods_spawning_threads = cpg.method.fullName(".*Thread.*").caller.fullName.l.distinct
```
#### result>
```
res28: List[String] = List(
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Update:System.Void()",
"SolarWinds.Orion.Core.BusinessLayer.BackgroundInventory.InventoryManager.RefreshInternal:System.Void()",
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.DelayMs:System.Void(System.Double,System.Double)",
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.HttpHelper.Close:System.Void(SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.HttpHelper,System.Threading.Thread)"
)
```

### Now verify which instance (of a specific class) is being spawned in the thread above
```
val instance_spawned = cpg.call.code(".*Thread.*").map(_.argument.isMethodRef.referencedMethod.fullName.l).l.flatten
```
#### result>
```
instance_spawned: List[String] = List(
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Initialize:System.Void()",
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.HttpHelper.Initialize:System.Void()"
)
```

### Affinity checks to determine name of current running process is always suspicious

```
val checking_process_name = cpg.call.name(Operators.equals).where(_.argument.order(2).isLiteral).where(_.argument.order(1).isCall.argument.code(".*Process.GetCurrentProcess.*ProcessName.*")).code.l
```

#### result>
```
checking_process_name: List[String] = List(
"OrionImprovementBusinessLayer.GetHash(Process.GetCurrentProcess().ProcessName.ToLower()) == 17291806236368054941UL"
)
```
### Conducting date interval checks in a control loop is always suspicious especially if the control block is executing obfuscated commands

```
val time_checks = cpg.call.code(".*DateTime.*Now.*CompareTo.*").callee.caller.map(i => (i.fullName, i.lineNumber, i.filename)).l
```

#### result>
```
…
time_checks: List[(String, Option[Integer], String)] = List(
(
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Initialize:System.Void()",
Some(110),
"SolarWinds.Orion.Core.BusinessLayer/BusinessLayer/OrionImprovementBusinessLayer.cs"
),
(
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.IsNullOrInvalidName:System.Boolean(System.String)",
Some(419),
"SolarWinds.Orion.Core.BusinessLayer/BusinessLayer/OrionImprovementBusinessLayer.cs"
),
(
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.DelayMs:System.Void(System.Double,System.Double)",
Some(447),
"SolarWinds.Orion.Core.BusinessLayer/BusinessLayer/OrionImprovementBusinessLayer.cs"
),
….
```

 ###  Creating a NamedPipeServer stream for async/sync R/W operations is a RED FLAG. Get all methods creating a named pipe
```
val methods_with_namedpipes = cpg.call.code(".*NamedPipeServerStream.*").callee.caller.map(i => (i.fullName, i.lineNumber, i.filename)).l
```

#### result>

```
…
methods_with_namedpipes: List[(String, Option[Integer], String)] = List(
(
"SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Initialize:System.Void()",
Some(110),
"SolarWinds.Orion.Core.BusinessLayer/BusinessLayer/OrionImprovementBusinessLayer.cs"
))

…
```

### Object utility to convert a given string literal to FNV-1a

```
object FNV {
private val INIT32 = BigInt("811c9dc5", 16);
private val INIT64 = BigInt("cbf29ce484222325", 16);
private val PRIME32 = BigInt("01000193", 16);
private val PRIME64 = BigInt("100000001b3", 16);
private val MOD32 = BigInt("2").pow(32);
private val MOD64 = BigInt("2").pow(64);
private val MASK = 0xff

@inline private final def calc(prime: BigInt, mod: BigInt)(hash: BigInt, b: Byte): BigInt = ((hash * prime) % mod) ^ (b & MASK)
@inline private final def calcA(prime: BigInt, mod: BigInt)(hash: BigInt, b: Byte): BigInt = ((hash ^ (b & MASK)) * prime) % mod

/**
* Calculates 32bit FNV-1 hash
* @param data the data to be hashed
* @return a 32bit hash value
*/
@inline final def hash32(data: Array[Byte]): BigInt = data.foldLeft(INIT32)(calc(PRIME32, MOD32))

/**
* Calculates 32bit FNV-1a hash
* @param data the data to be hashed
* @return a 32bit hash value
*/
@inline final def hash32a(data: Array[Byte]): BigInt = data.foldLeft(INIT32)(calcA(PRIME32, MOD32))

/**
* Calculates 64bit FNV-1 hash
* @param data the data to be hashed
* @return a 64bit hash value
*/
@inline final def hash64(data: Array[Byte]): BigInt = data.foldLeft(INIT64)(calc(PRIME64, MOD64))

/**
* Calculates 64bit FNV-1a hash
* @param data the data to be hashed
* @return a 64bit hash value
*/

@inline final def hash64a(data: Array[Byte]): BigInt = data.foldLeft(INIT64)(calcA(PRIME64, MOD64))
}

```



### Sunburst checks for the following running processes on host (to determine dormancy or execute)

```

val process_blacklist = Set(
"apimonitor-x64",
"apimonitor-x86",
"autopsy64",
"autopsy",
"autoruns64",
"autoruns",
"autorunsc64",
"autorunsc",
"binaryninja",
"blacklight",
"cff explorer",
"cutter",
"de4dot",
"debugview",
"diskmon",
"dnsd",
"dnspy",
"dotpeek32",
"dotpeek64",
"dumpcap",
"evidence center",
"exeinfope",
"fakedns",
"fakenet",
"ffdec",
"fiddler",
"fileinsight",
"floss",
"gdb",
"hiew32demo",
"hiew32",
"hollows_hunter",
"idaq64",
"idaq",
"idr",
"ildasm",
"ilspy",
"jd-gui",
"lordpe",
"officemalscanner",
"ollydbg",
"pdfstreamdumper",
"pe-bear",
"pebrowse64",
"peid",
"pe-sieve32",
"pe-sieve64",
"pestudio",
"peview",
"ppee",
"procdump64",
"procdump",
"processhacker",
"procexp64",
"procexp",
"procmon",
"prodiscoverbasic",
"py2exedecompiler",
"r2agent",
"rabin2",
"radare2",
"ramcapture64",
"ramcapture",
"reflector",
"regmon",
"resourcehacker",
"retdec-ar-extractor",
"retdec-bin2llvmir",
"retdec-bin2pat",
"retdec-config",
"retdec-fileinfo",
"retdec-getsig",
"retdec-idr2pat",
"retdec-llvmir2hll",
"retdec-macho-extractor",
"retdec-pat2yara",
"retdec-stacofin",
"retdec-unpacker",
"retdec-yarac",
"rundotnetdll",
"sbiesvc",
"scdbg",
"scylla_x64",
"scylla_x86",
"shellcode_launcher",
"solarwindsdiagnostics",
"sysmon64",
"task explorer",
"task explorer-x64",
"tcpdump",
"tcpvcon",
"tcpview",
"vboxservice",
"win32_remote",
"win64_remotex64",
"windbg",
"windump",
"winhex64",
"winhex",
"winobj",
"wireshark",
"x32dbg",
"x64dbg",
"xwforensics64",
"xwforensics",
"redcloak",
"avgsvc",
"avgui",
"avgsvca",
"avgidsagent",
"avgsvcx",
"avgwdsvcx",
"avgadminclientservice",
"afwserv",
"avastui",
"avastsvc",
"aswidsagent",
"aswidsagenta",
"aswengsrv",
"avastavwrapper",
"bccavsvc",
"psanhost",
"psuaservice",
"psuamain",
"avp",
"avpui",
"ksde",
"ksdeui",
"tanium",
"taniumclient",
"taniumdetectengine",
"taniumendpointindex",
"taniumtracecli",
"taniumtracewebsocketclient64"
)

```



### Compute FNV-1a for process blacklist

```
val process_fnv_tuples = process_blacklist.map { i =>
	val seed = 6605813339339102567L
	val op = FNV.hash64a(i.getBytes) ^ seed
	(i, op, op.toString + "L")
}
```

### Verify if obfuscated hashes are encoded in literals
```
val obfuscated_process_checks = process_fnv_tuples.map(_._3).toSet.intersect(all_literals)
```

### Sunburst checks for the following running services on host (to determine dormancy or execute)

```
val services_blacklist : Map[String, Set[String]] = Map(
"Windows Defender" -> Set("msmpeng","windefend"),
"Windows Sense" -> Set("mssense","sense"),
"Windows Sensor" -> Set("microsoft.tri.sensor","microsoft.tri.sensor.updater"),
"NIST" -> Set("cavp"),
"Carbon Black" -> Set(
"cb",
"carbonblack",
"carbonblackk",
"cbcomms",
"cbstream"),
"CrowdStrike" -> Set(
"csfalconservice",
"csfalconcontainer",
"csagent",
"csdevicecontrol",
"csfalconservice"),
"FireEye" -> Set(
"xagt",
"xagtnotif",
"fe_avk",
"fekern",
"feelam",
"fewscservice"),
"ESET" -> Set(
"ekrn",
"eguiproxy",
"egui",
"eamonm",
"eelam",
"ehdrv",
"ekrnepfw",
"epfwwfp",
"ekbdflt",
"epfw"),
"F-SECURE" -> Set(
"fsgk32st",
"fswebuid",
"fsgk32",
"fsma32",
"fssm32",
"fnrb32",
"fsaua",
"fsorsp",
"fsav32",
"f-secure gatekeeper handler starter",
"f-secure network request broker",
"f-secure webui daemon",
"fsma",
"fsorspclient",
"f-secure gatekeeper",
"f-secure hips",
"fsbts",
"fsni",
"fsvista",
"f-secure filter",
"f-secure recognizer",
"fses",
"fsfw",
"fsdfw",
"fsms",
"fsdevcon")
)

```

### Compute FNV-1a for services blacklist

```

val process_fnv_services = services_blacklist.values.flatten.map { i =>
	val seed = 6605813339339102567L
	val op = FNV.hash64a(i.getBytes) ^ seed
	op.toString + "L"
}

```

### Verify if obfuscated hashes are encoded in literals

```
val obfuscated_services_checks = process_fnv_services.toSet.intersect(all_literals)
```



### Sunburst checks for the following running drivers on host (to determine dormancy or execute)

```
val driver_blacklist = Set(
"cybkerneltracker.sys",
"atrsdfw.sys",
"eaw.sys",
"rvsavd.sys",
"dgdmk.sys",
"sentinelmonitor.sys",
"hexisfsmonitor.sys",
"groundling32.sys",
"groundling64.sys",
"safe-agent.sys",
"crexecprev.sys",
"psepfilter.sys",
"cve.sys",
"brfilter.sys",
"brcow_x_x_x_x.sysv",
"lragentmf.sys",
"libwamf.sys");

```

### Compute FNV-1a for driver blacklist

```
val process_fnv_services = driver_blacklist.map { i =>
	val seed = 6605813339339102567L
	val op = FNV.hash64a(i.getBytes) ^ seed
	op + "L"
}
```

### Verify if obfuscated hashes are encoded in literals

```
val obfuscated_driver_checks = process_fnv_services.toSet.intersect(all_literals)
```



### Sunburst checks for the following running drivers on host (to determine dormancy or execute)

```
val domain_blacklist = Set(
"swdev.local",
"swdev.dmz",
"lab.localv",
"lab.na",
"emea.sales",
"cork.lab",
"dev.local",
"dmz.local",
"pci.local",
"saas.swi",
"lab.rio",
"lab.brno",
"apac.lab");

```



### Compute FNV-1a for domain blacklist

```
val process_fnv_domain = domain_blacklist.map { i =>
	val seed = 6605813339339102567L
	val op = FNV.hash64a(i.getBytes) ^ seed
	op
}

```

### Verify if obfuscated hashes are encoded in literals

```
val obfuscated_domain_checks = process_fnv_domain.toSet.intersect(all_literals)
```



### Sunburst obfuscates HTTPS based communication with C2 server

```
val obfuscated_http_codes = Set(
	"expect",
	"content-type",
	"accept",
	"content-type",
	"user-agent",
	"100-continue",
	"connection",
	"referer",
	"keep-alive",
	"close",
	"if-modified-since",
	"date"
)
```

### Compute FNV-1a for domain blacklist

```
val http_codes = obfuscated_http_codes.map { i =>
	val seed = 6605813339339102567L
	val op = FNV.hash64a(i.getBytes) ^ seed
	op
}
```

### Verify if obfuscated hashes are encoded in literals

```
val http_comm_checks = http_codes.toSet.intersect(all_literals)
```
