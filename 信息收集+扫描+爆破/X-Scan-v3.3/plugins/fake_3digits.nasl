#
# (C) Tenable Network Security, Inc.
#

# This script was written by Michel Arboi <mikhail@nessus.org>
#


include("compat.inc");

if(description)
{
 script_id(32376);
 script_version ("$Revision: 1.7 $");
 script_name(english:"Fake SMTP/FTP Server (possible backdoor)");
 script_set_attribute(attribute:"synopsis", value:
"The remote service seems to be a backdoor" );
 script_set_attribute(attribute:"description", value:
"Although this service answers with 3 digit ASCII codes
like FTP, SMTP or NNTP servers, it sends back different codes
when several NOOP commands are sent in a row.

This is probably a backdoor; in this case, your system is 
compromised and a cracker can control it remotely." );
 script_set_attribute(attribute:"solution", value:
"Disinfect or reinstall your operating system" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english: "Checks that the '3 digits' server answers correctly");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Backdoors");
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/three_digits");
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');

# I'm not sure this will not generate FP
if (! experimental_scripts) exit(0);

port = get_kb_item("Services/three_digits");
# port = 25;	# TEST
if (! port || ! get_port_state(port)) exit(0);

function read3(socket)
{
 local_var	all, r, lines, n, i;

 all = '';
 for (i = 0; i < 10; i ++)
 {
  r = recv(socket: socket, length: 2048);
  if (strlen(r) == 0)
  {
    debug_print('Timeout?\n');
    break;
  }
  all = strcat(all, r);
  lines = split(all);
  n = max_index(lines)-1;
  if (ereg(string: lines[n], pattern: '^[0-9][0-9][0-9][^-]'))
   break;
  lines = NULL;
 }
 if (i >= 10) debug_print('Response too big\n');
 if (isnull(lines))
 {
  lines = split(all);
  n = max_index(lines)-1;
  if (n < 0) return NULL;
 }
 return lines[n];
}

soc = open_sock_tcp(port);
if (!soc) exit(0);

r = read3(socket: soc);
if (r !~ '^[0-9][0-9][0-9]')
{
 debug_print('No 3 digit banner\n');
 close(soc);
 exit(0);
}

for (i = 1; i < 5; i ++)
{
 if (send(socket: soc, data: 'NOOP\r\n') < 6)
 {
  debug_print('Broken pipe on try #', i, '\n');
  break;
 }
 r = read3(socket: soc);
 if (strlen(r) == 0) break;
 if (r !~ '^[0-9][0-9][0-9]')
 {
  debug_print('No 3 digit answer\n');
  code[i] = r;
 }
 else
  code[i] = substr(r, 0, 2);
 debug_print('code[',i,']=', code[i], '\n');
}

prev = code[1]; n = max_index(code); flag = 0;
for (i = 2; i < max_index(code); i ++)
{
 if (prev != code[i])
 {
  debug_print('code[',i,']=',code[i], ' <> code[',i-1, ']=',code[i-1],'\n');
# Some (proxy?) servers rejects too many similar commands in a row
  if (code[i] != '421' && code[i] != '554')
   flag ++;
 }
 prev = code[i];
}

send(socket: soc, data: 'QUIT\r\n');
close(soc);

if (flag)
{
 security_hole(port);
 svc = known_service(port: port);
 if (svc == 'smtp')
 {
  set_kb_item(name: 'smtp/'+port+'/broken', value: TRUE);
  if (port == 25)
   set_kb_item(name: 'SMTP/wrapped', value: TRUE);
 }
 if (svc == 'ftp')
 {
  set_kb_item(name: 'ftp/'+port+'/broken', value: TRUE);
  set_kb_item(name: 'ftp/'+port+'/backdoor', value: TRUE);
 }
 set_kb_item(name: 'backdoor/TCP/'+port, value: TRUE);
}
