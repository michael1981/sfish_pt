#TRUSTED 5df1074b9ce9c0695f08f77b31b9dbebd500d465225b8c15ebf45110bf370a8be21f522db6b3f260887bfbd6d92c057a7b7a33a97c18233ac224ca87b0c9e53a6e76cdea8a01cbaa5f808ded05d17e9454f3f012d5caebb0280948e556d18d6f8887e8d3c1d4524e96cda6c45a634325378e986f5e4eb7e4b40fbac5037337360d1ef48807138a1cac38e3a5735cf3f326c41b73b3660ce298d32bbd1e4973fb013a8a9cf8b49ba864628f68e245a3b7bc99a286574e436685994f3b7f6e29bf507c1f8af980842480ba5391b1d11c93cedf9b17f18f1d94a3aab5c52304aa968ff5ba0468ad62f30cf6ad202499eaec2d05271ad6c8107ec307307ab36748d56564b91b4a4df9856e248358cd1b1fe55c51f9e21d3439a6515ae6faaf60343d696bf04d5fca9df539ae5edee251fc39a1e39866258accaf7e97a10935323a8cf6cd79e73a3bdb29a5c8b78aa0b4ef01c78e754dce3c00bd25b4cf03bf9109948734c9e365774dab4fab999d9d94467c41c19d8573b988d50250c7296f2976c700d7e650806623eb1f16c01d1b9acc5076b656c8f63c14f35dae1ea4565f1aa6344279b62843bc174142fefe65ba43fdee85bf1a60c8e796480aab6978299fdbed7cab346ad94cce66d5362bb205e66585774440889f7152466396ce125bde507eea6d69da51c3f9efdc9e514dc458cc95aeae19f68931f5db77216fc823de73
#
# This script was written by Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(32314);
 script_version ("1.2");

 script_cve_id("CVE-2008-0166");
 script_bugtraq_id(29179);

 name["english"] = "Debian OpenSSH/OpenSSL Package Random Number Generator Weakness";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH host keys are weak." );
 script_set_attribute(attribute:"description", value:
"The remote SSH host key has been generated on a Debian 
or Ubuntu system which contains a bug in the random number
generator of its OpenSSL library.

The problem is due to a Debian packager removing nearly all
sources of entropy in the remote version of OpenSSL.

An attacker can easily obtain the private part of the remote
key and use this to set up decipher the remote session  or
set up a man in the middle attack." );
 script_set_attribute(attribute:"solution", value:
"Consider all cryptographic material generated on the remote host
to be guessable. In particuliar, all SSH, SSL and OpenVPN key
material should be re-generated." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d01bdab (Debian)" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f14f4224 (Ubuntu)" );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
	
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH public key fingerprint");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008 Tenable Network Security, Inc");
 script_family(english:"Gain a shell remotely");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


include("byte_func.inc");
include("ssh_func.inc");

SSH_RSA = 0;
SSH_DSS = 1;



function file_read_dword(fd)
{
 local_var dword;

 dword = file_read(fp:fd, length:4);
 dword = getdword(blob:dword, pos:0);

 return dword;
}


function find_hash_list(type, first, second)
{
 local_var list, fd, i, j, main_index, sec_index, c, offset, length, len, pos, file;
 local_var tmp_list;

 if (type == SSH_RSA)
   file = "blacklist_rsa.inc";
 else if (type == SSH_DSS)
   file = "blacklist_dss.inc";

 if ( ! file_stat(file) ) return NULL;

 fd = file_open(name:file, mode:"r");
 if (!fd) return NULL;

 main_index = file_read_dword(fd:fd);

 for (i=0; i<main_index; i++)
 {
  c = file_read(fp:fd, length:1);
  offset = file_read_dword(fd:fd);
  length = file_read_dword(fd:fd);

  if (c == first)
  {
   file_seek(fp:fd, offset:offset);
   sec_index = file_read_dword(fd:fd);

   for (j=0; j<sec_index; j++)
   {
    c = file_read(fp:fd, length:1);
    offset = file_read_dword(fd:fd);
    length = file_read_dword(fd:fd);

    if (c == second)
    {
     file_seek(fp:fd, offset:offset);
     tmp_list = file_read(fp:fd, length:length);

     len = strlen(tmp_list);
     pos = 0;

     for (j=0; j<len; j+=10)
       list[pos++] = substr(tmp_list, j, j+9);

     break;
    }
   }

   break;
  }
 }

 file_close(fd);

 return list;
}

function is_vulnerable_fingerprint(type, fp)
{
 local_var list, i, len;

 list = find_hash_list(type:type, first:fp[0], second:fp[1]);
 if (isnull(list))
   return FALSE;

 len = max_index(list);
 
 for (i=0; i<len; i++)
   if (list[i] == fp)
     return TRUE;

 return FALSE;
}

fingerprint = get_kb_item("SSH/Fingerprint/ssh-rsa");
if (fingerprint)
{
 ret = is_vulnerable_fingerprint(type:SSH_RSA, fp:substr(ssh_hex2raw(s:fingerprint), 6, 15));
 if (ret)
   security_hole(port:kb_ssh_transport());
}

fingerprint = get_kb_item("SSH/Fingerprint/ssh-dss");
if (fingerprint)
{ 
 ret = is_vulnerable_fingerprint(type:SSH_DSS, fp:substr(ssh_hex2raw(s:fingerprint), 6, 15));
 if (ret)
   security_hole(port:kb_ssh_transport());
}
