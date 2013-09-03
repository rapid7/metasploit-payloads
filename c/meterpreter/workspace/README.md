Build Requirements
==================

Meterpreter can be built with [Visual Studio 2012 Express for Desktop][vs_express] or any
paid version of [Visual Studio 2012][vs_paid]. Earlier toolsets on Windows are no longer
supported.

Visual Studio 2012 requires .NET 4.5 in order to run, and as a result isn't compatible
with Windows XP due to the fact that .NET 4.5 will not run on Windows XP. However, this
does not mean that Metepreter itself will not run on Windows XP, it just means that it's
not possible to _build_ it on Windows XP.

    [vs_express]: http://www.microsoft.com/visualstudio/eng/downloads#d-2012-express
    [vs_paid]: http://www.microsoft.com/visualstudio/eng/downloads#d-2012-editions