# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-03.xml
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
 script_id(29907);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200801-03");
 script_cve_id("CVE-2007-6208");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-03
(Claws Mail: Insecure temporary file creation)


    Nico Golde from Debian reported that the sylprint.pl script that is
    part of the Claws Mail tools creates temporary files in an insecure
    manner.
  
Impact

    A local attacker could exploit this vulnerability to conduct symlink
    attacks to overwrite files with the privileges of the user running
    Claws Mail.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Claws Mail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/claws-mail-3.0.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6208');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-03] Claws Mail: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Claws Mail: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/claws-mail", unaffected: make_list("ge 3.0.2-r1"), vulnerable: make_list("lt 3.0.2-r1")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
