# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(16446);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200502-09");
 script_cve_id("CVE-2005-0089");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-09
(Python: Arbitrary code execution through SimpleXMLRPCServer)


    Graham Dumpleton discovered that XML-RPC servers making use of the
    SimpleXMLRPCServer library that use the register_instance() method to
    register an object without a _dispatch() method are vulnerable to a
    flaw allowing to read or modify globals of the associated module.
  
Impact

    A remote attacker may be able to exploit the flaw in such XML-RPC
    servers to execute arbitrary code on the server host with the rights of
    the XML-RPC server.
  
Workaround

    Python users that don\'t make use of any SimpleXMLRPCServer-based
    XML-RPC servers, or making use of servers using only the
    register_function() method are not affected.
  
');
script_set_attribute(attribute:'solution', value: '
    All Python users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/python
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0089');
script_set_attribute(attribute: 'see_also', value: 'http://www.python.org/security/PSF-2005-001/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-09] Python: Arbitrary code execution through SimpleXMLRPCServer');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: Arbitrary code execution through SimpleXMLRPCServer');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("ge 2.3.4-r1", "rge 2.3.3-r2", "rge 2.2.3-r6"), vulnerable: make_list("le 2.3.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
