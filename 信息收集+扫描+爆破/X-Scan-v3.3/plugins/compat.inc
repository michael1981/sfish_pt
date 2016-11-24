#TRUSTED 5d14f3b876c07f0cc3b54885fd9d0979bff4ef2b9bded207400d7fe3064e7005549546cbc84dac02216696b5487318660a6c2a9efd6eeb79dd644d383fe86caebe18091bfe8b64f4f86fe752098683a5ef052210b13b1c58b382a890ec7717b63499948c0808038827bf85ba9ea696d58003ebee268aea4fbfa0a3c2bd26be4c6b25a28f16790fbd32e830c3b403bbb0dc0d527bec8fdada2f74cc6a99d18daf69f62849874f946905fdb139a6ff7710f2a46fb4c104f3ec54b3543bcd6d31b2e1f36686448e1ff6ef72b300f6fb912e183717665fa86e2d5d19b37804c0b8f32f51bfd2cace47e0a5fb7af4469534b1d078f0fe198d843109dda399bf785154d7dd7a17777d392d38dbc18bf90ff90bf391e976b4e8cf2961543dbc07b0a9764d57a1c55191618ba71b52104295b253259bff2b7be25ac94b05797811cdf6b3f810a54495e1c8b54a01cfe23e04172f0542441c7e5c0c59ffc5de128a5df22ee695a3d1582caaab103716e8f26dc365146d6d4344d1d473bb7f45759b7687862e24e271cd409b5fe0efbffc5dd5126b9a336fa1dcdfbe8ddc901a22deb63f26091312ad93337830d5b53311032ac15a26b111c043959b90ec5727bea2feccfeccb7f0ad372fbb8f7393d2d09de82627b316e3473743ada9b690824848becab265efe602e56458886b63b9d816b6d20125234edebad3d89c339d4201fc8b0565
#
# 
# (C) Tenable Network Security, Inc.
#
# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#     This product includes software developed by Tenable Network Security
#
# Revision 1.5

#
# Backward compatibility functions
#
__desc_buf = NULL;



function cvss_vector_to_base_score()
{
 local_var str;
 local_var c,i,a;
 local_var AccessVector, AccessComplexity, Authentication;
 local_var q,z;
 local_var cvss_score;

 str = _FCT_ANON_ARGS[0];
 if ( "AV:L/" >< str )
   AccessVector = 2532;
 else if ( "AV:A/" >< str )
   AccessVector = 1548;
 else if ( "AV:N/" >< str)
   AccessVector = 1000;
 else 
 {
   #display("Unknown CVSS access subvector (", str, ")!\n");
   return NULL;
 }

 if ( "AC:L/" >< str )
   AccessComplexity = 1408;
 else if ( "AC:M/" >< str )
   AccessComplexity = 1639;
 else if ( "AC:H/" >< str )
   AccessComplexity = 2857;
 else 
 {
   #display("Unknown CVSS access complexity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "Au:N/" >< str )
   Authentication = 1420;
 else if ( "Au:S/" >< str )
   Authentication = 1786;
 else if ( "Au:M/" >< str )
   Authentication = 2222;
 else 
 {
   #display("Unknown CVSS authentication subvector (", str, ")!\n");
   return NULL;
 }

 if ( "C:N/" >< str )
   c = 1000;
 else if ( "C:P/" >< str )
   c = 725;
 else if ( "C:C/" >< str )
   c = 340;
 else 
 {
   #display("Unknown CVSS confidentiality subvector (", str, ")!\n");
   return NULL;
 }

 if ( "I:N/" >< str )
   i = 1000;
 else if ( "I:P/" >< str )
   i = 725;
 else if ( "I:C/" >< str )
   i = 340;
 else 
 {
   #display("Unknown CVSS integrity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "/A:N" >< str )
   a = 1000;
 else if ( "/A:P" >< str )
   a = 725;
 else if ( "/A:C" >< str )
   a = 340;
 else 
 {
   #display("Unknown CVSS availability subvector (", str, ")!\n");
   return NULL;
 }

 if ( c + i + a == 3000 )
   return "0.0";

 z = (c*1000)/( (1000*1000)/i);
 z = (z*1000)/( (1000*1000)/a);
 z = 1000 - z;
 z = (1000*1000)/z;
 z = (10410*1000)/z;
 z = (z*1000)/1666;

 q = ( AccessComplexity  * 1000 ) / (( 1000 * 1000 )/Authentication );
 q = ( q * 1000 ) / ( ( 1000 * 1000 ) / AccessVector );
 q = ( 1000 * 1000 ) / q;
 q = q * 20000;
 q = q / 2500;

 z = ( z + q ) - 1500;
 z = (z * 11760)/10000;
 if ( z % 100 >= 50) z += ( 100 - (z % 100) ); # Rounding
 if ( z / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( z % 100 >= 40) z += ( 100 - (z % 100) ); 
 }
 
 z = (z/10)*10;
 cvss_score = strcat(z / 1000, ".", (z % 1000)/100);
 return cvss_score;
}



function script_set_attribute(attribute, value)
{
 local_var s, e;
 local_var i;

 if ( isnull(attribute) || isnull(value) ) return;
 value = '' + value;
 e = strlen(value);
 for ( i = 0 ; value[i] >< ' \t\n\r' && i < e ; i ++ ) { };
 for ( e = strlen(value) - 1; value[e] >< ' \t\n\r' && e > 0 ; e -- ) { };
 value = substr(value, i, e);
 if ( strlen(__desc_buf[attribute]) ) __desc_buf[attribute] += '\n';
 __desc_buf[attribute] += value;
}


function script_end_attributes()
{
 local_var r;
 local_var buf;


 if ( isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_vector"]) )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(__desc_buf["cvss_vector"]);


 if ( isnull(__desc_buf["risk_factor"]) )
 {
  if ( isnull(__desc_buf["cvss_base_score"]) )
	__desc_buf["risk_factor"] = "None";
  else {
   if ( int(__desc_buf["cvss_base_score"]) == 10 ) __desc_buf["risk_factor"] = "Critical";
   else if ( int(__desc_buf["cvss_base_score"]) >= 7 ) __desc_buf["risk_factor"] = "High";
   else if ( int(__desc_buf["cvss_base_score"]) >= 4 ) __desc_buf["risk_factor"] = "Medium";
   else if ( int(__desc_buf["cvss_base_score"]) > 0 ) __desc_buf["risk_factor"] = "Low";
   else __desc_buf["risk_factor"] = "None";
  }
 }



 buf = "";
 r = __desc_buf["synopsis"];
 if ( strlen(r) )
 {
   buf += 'Synopsis :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["description"];
 if ( strlen(r) )
 {
   buf += 'Description :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["see_also"];
 if ( strlen(r) )
 {
   buf += 'See also :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["solution"];
 if ( strlen(r) )
 {
   buf += 'Solution :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["risk_factor"];
 if ( strlen(r) )
 {
   buf += 'Risk factor :\n\n';
   buf += r;
   r = __desc_buf["cvss_base_score"];
   if ( r ) {
	buf += " / CVSS Base Score : " + r;
	r = __desc_buf["cvss_vector"];	
	if ( r ) buf += '\n(' + r + ')\n';
    	else buf += '\n';
    }
    else buf += '\n';
 }
 
 if ( NASL_LEVEL < 3000 && strlen(buf) >= 3000 ) exit(0);
 script_description(buf);
}
