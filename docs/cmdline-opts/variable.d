c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: variable
Arg: <[%]name=text/@file>
Help: Set variable
Category: curl
Example: --variable name=smith $URL
Added: 8.3.0
See-also: config
Multi: append
---
Set a variable with "name=content" or "name@file" (where "file" can be stdin
if set to a single dash (-)). The name is a case sensitive identifier that
must consist of no other letters than a-z, A-Z, 0-9 or underscore. The
specified content is then associated with this identifier.

The name must be unique within a command line invoke, setting the same
variable name again will be ignored.

The contents of a variable can be referenced in a later command line option
when that option name is prefixed with "--expand-", and the name is used as
"{{name}}" (without the quotes).

--variable can import environment variables into the name space. Opt to either
require the environment variable to be set or provide a default value for the
variable in case it is not already set.

--variable %name imports the variable called 'name' but exits with an error if
that environment variable is not alreadty set. To provide a default value if
the environment variable is not set, use --variable %name=content or
--variable %name@content.

When expanding variables, curl supports a set of functions that can make the
variable contents more convenient to use. It can trim leading and trailing
white space with "trim", it can output the contents as a JSON quoted string
with "json" and it can URL encode the string with "urlencode". You apply
function to a variable expansion, add them colon separated to the right side
of the variable. Variable content holding null bytes that are not encoded when
expanded, will cause error.

The variable expansion feature offers a few functions that can help you get
the value inserted more conveniently. Append the function to the name,
separated by a colon.

":trim" removes all leading and trailing white space.

":json" outputs the content using JSON string quoting rules.

":percent" shows the content URL (percent) encoded.
