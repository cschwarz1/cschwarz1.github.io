---
title: "Kernel Driver Stack Smashing"
date: 2023-02-07T01:28:11+01:00
draft: false
description: "First part of the series on how to develop an implant for internal 
			  security assessments"
---

# intro

In this blog post series we will take a look on we can leverage kernel driver vulnerabilites to execute arbitrary ring-0 privileged code on a fully patched win10 2202 system, how to bypass some of the current kernel protections and some caveats and pitfalls one might encounter.
At this point I can not share the specific kernel driver I used for the exploitation, as this is stil under an embargo due to responsible disclosure. The concepts however will apply to most stack based overflow vulnerabilities in kernel drivers. 

Why are we doing this ?

Througout the development of the implant we assume admin privileges on a compromised host, either through stolen credentials, DNS Fallback account take-overs, compromised misconfigured web applications, etc.

Our implant will load a signed driver to execute ring-0 code and hook, bypass or simply kill the AV/EDR. We will take a look on how we can interrupt or forge telemetry and how we deal with PPL ([Protected Processes Light]) and on how we can deal with VBS. 

So we made a plan, let's see how far this goes. I'll not publish detailled findings and code but if you familirize yourself with the concepts it should be doable to write your own implant you can use in your engagements. After all these concepts and techniques ar all over the internet and researched already, we will just combine the best fitting ones and throw together some code we can activley use for AV/EDR evasion.


==highlight==
<span style="color:red"> *some emphasized markdown text*</span>


**My Bold Text, in red color.**{: style="color: red; opacity: 0.80;" }



```html
<section id="main">
  <div>
   <h1 id="title">{{ .Title }}</h1>
    {{ range .Pages }}
        {{ .Render "summary"}}
    {{ end }}
  </div>
</section>
```


#### A blue heading
{: .blue}


I highly suggest `researching` your own vulnerable driver as these technique will probably be valueable for quite some time. VBS is still early and think on how many win2003/win2008 server boxes are still lurking around in intranets nowadys. Kernel driver based (BYOVD) attack paths are here to stay for the foreseeable future. 

So grab your [HVKD] or research your own vulnerable driver and let's go. 

```powershell
@echo off

SETLOCAL ENABLEDELAYEDEXPANSION

for /r . %%a in (*.sys) do (

        set full_path=%%a
        set filename_ext=%%~nxa
        set filename=%%~na
        set extension=%%~xa
        
        dumpbin /imports !filename_ext! | findstr /i /M %1

        if !errorlevel!==0 (
                echo !filename!
        )
)
```

```Batchfile
@echo off

SETLOCAL ENABLEDELAYEDEXPANSION

for /f "tokens=*" %%a in (driver_list.txt) do (

    set full_path=%%a
    set filename_ext=%%~nxa
    set filename=%%~na

    copy !full_path! C:\local_files\drivers\

    signtool.exe verify /pa C:\local_files\drivers\!filename_ext!
    
    if !errorlevel!==0 (
        sc stop !filename!
        sc delete !filename!
        echo "creating service !filename! whith path C:\local_files\drivers\!filename_ext!"
        sc create !filename! binpath=C:\local_files\working_drivers\!filename_ext! type=kernel
        echo "starting service !filename!"
        echo !full_path! >> output.txt
        sc start !filename!
        if !errorlevel! == 0 (
            echo !full_path! >> success.txt
        )
    ) 
)
```


`tsteasd 1231`




# quick overview kernel drivers and how to research your own

- fuzzy security
- excellent blog connor
- voidsec
- jackson_t




# stack buffer overflows

