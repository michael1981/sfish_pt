# -*- Fundamental -*-
# (C) Tenable Network Security
# 
#
# An earlier iteration of this file was written by George Dagousset (2002)
#
# This include file is released under the terms of the GPLv2
#


function line2string (line, linenumber)
{
 local_var tmp, pos;

 line = line*16;
 tmp = raw_string (
	(line >> 24) & 0xFF,
	(line >> 16) & 0xFF,
	(line >> 8) & 0xFF,
	(line ) & 0xFF
	);

 if (linenumber < 256)
   pos = 3;
 else if (linenumber < 65536)
   pos = 2;
 else if (linenumber < 16777216)
   pos = 1;
 else
   pos = 0;

 return string ("0x", toupper(hexstr(substr (tmp, pos, 3))), ": ");
}


function isprint (c)
{
 if ( (ord(c) >= 0x20) && (ord(c) <= 0x7E) )
   return TRUE;

 return FALSE;
}


function dump_line_and_data(str, linenb, totallen)
{
  local_var	j, len, c, line, data;

  line = line2string (line: linenb, linenumber: totallen);
  len = strlen(str);

  for (j = 0; j < 16; j++)
  {
   if (j < len )
   {
    line = strcat(line, " ", toupper(hexstr(str[j])));
    c = str[j];
    if (isprint (c:c))
      data += c;
    else
      data += ".";
   }
   else
   {
    line += "   ";
    data += " ";
   }
  }
  return  strcat(line, '    ', data, '\n');
}

function hexdump (ddata)
{
 local_var tmp, i, linenumber, len;
 local_var	same_str_cnt, prev_str, prev_adr, str;

 len = strlen(ddata);
 linenumber = len / 16;

 prev_str = NULL; same_str_cnt = 0; prev_adr = 0;

 for (i = 0; i <= linenumber; i++)
 {
  str = substr(ddata, i*16, i*16+15);
  if (! isnull(prev_str))
  {
    if (str == prev_str)
    {
      same_str_cnt ++;
      continue;
    }
#    else if (same_str_cnt == 1)
#    {
#      tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);    
#    }
#    else if (same_str_cnt > 1)
    else if (same_str_cnt >= 1)
      tmp += '*\n';    
  }
  prev_str = str; same_str_cnt = 0;
  tmp += dump_line_and_data(str: str, linenb: i, totallen: len);
 }

 if (same_str_cnt > 0)	# Should not happen!
   tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);
 return tmp;
}
 

function dump( dtitle, ddata )
{
 if( ! isnull( dtitle ) )
	display('---[ ' + dtitle + ' ]---\n' );


 display(hexdump(ddata:ddata));
}

