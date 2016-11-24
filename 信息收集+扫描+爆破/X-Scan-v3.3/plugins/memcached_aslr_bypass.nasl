#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38207);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-1255");
  script_bugtraq_id(34756);
  script_xref(name:"OSVDB", value:"54127");
  script_xref(name:"Secunia", value:"34915");
  script_xref(name:"Secunia", value:"34932");

  script_name(english:"Memcached / MemcacheDB ASLR Bypass Weakness");
  script_summary(english:"Sends a 'stats maps' command");
 
  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote object store suffers from a weakness that may make buffer\n",
      "overflows easier to exploit."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of memcached / MemcacheDB running on the remote host\n",
      "reveals information about the stack, heap, and shared library memory\n",
      "locations it uses.  An unauthenticated remote attacker may be able to\n",
      "leverage this weakness to defeat any address space layout\n",
      "randomization (ASLR) protection on the remote host, thereby making\n",
      "buffer overflows easier to exploit."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.positronsecurity.com/advisories/2009-001.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://archives.neohapsis.com/archives/fulldisclosure/2009-04/0282.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?7ab1e482"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?a97219eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "If using memcached, upgrade to version 1.2.8.\n",
      "\n",
      "If using MemcacheDB, upgrade to revision r98 or later from the code\n",
      "repository."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("memcached_detect.nasl");
  script_require_ports("Services/memcached", 11211, 21201);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/memcached"), port:11211);
ports = add_port_in_list(list:ports, port:21201);

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  soc = open_sock_tcp(port);
  if (soc)
  {
    req = "stats maps";
    send(socket:soc, data:string(req, "\r\n"));
    res = recv(socket:soc, length:8192);

    # There's a problem if...
    if (
      # we get a response and...
      !isnull(res) && 
      (
        # either there's an error or...
        stridx(res, 'SERVER_ERROR ') == 0 ||
        # we see a map
        egrep(pattern:"^[0-9a-f]+-[0-9a-f]+[ 	][-r][-w][-x]p[ 	]", string:res)
      )
    )
    {
      if (report_verbosity > 0)
      {
        max_lines = 10;
        n = 0;
        output = "";

        foreach line (split(res, keep:TRUE))
        {
          output += line;
          if (n++ > max_lines) break;
        }
        report = string(
          "\n",
          "Here is the output of sending a '", req, "' command to the remote\n",
          "service :\n",
          "\n",
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
          output,
          crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
        );
        if (n < max_index(split(res)))
        {
          report = string(
            report,
            "\n",
            "Note that only the first ", max_lines, " lines of output are reported.\n"
          );
        }
        if (stridx(res, 'SERVER_ERROR ') == 0)
        {
          report = string(
            report,
            "\n",
            "Note that while the server responded with an error, the error itself\n",
            "indicates the weakness in the code is still present.\n"
          );
        }

        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }

    close(soc);
  }
}
