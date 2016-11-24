# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# webapp_func.inc
# $Revision: 1.2 $
#


# The calling plugin must include 'misc_func.inc' (for the base64 functions),
# and 'http.inc' (for the URL building function)


DIR_SEPARATOR= ';';
UNKNOWN_VER = 'unknown';
DEFAULT_HEADER = 'Nessus was able to verify the issue using the following URL';


# add_install
#
# adds install information to an array of existing install information, and
# saves the info to the KB
#
# args (* = required):
#  *appname  - name of installed application
#   installs - existing list of installs (formatted the same as the return
#              value of this function).
#  *dir      - dir of install to add
#   ver      - version of the install found in 'dir'. if no argument is given,
#              it will be given a version of UNKNOWN_VER
#  *port     - port number the app was detected on
#
# returns an array - 'installs', with the new install added.
#         key = version
#         dir = corresponding dirs, delimited by DIR_SEPARATOR
#
function add_install(appname, installs, dir, ver, port)
{
  if (isnull(appname)) return NULL;
  if (isnull(dir)) return NULL;
  if (isnull(port)) return NULL;
  if (isnull(installs)) installs = make_array();
  if (isnull(ver)) ver = UNKNOWN_VER;

  if (dir == '') dir = '/';

  set_kb_item(
    name:'www/' + port + '/' + appname,
    value:ver + ' under ' + dir
  );

  # base64 encodes dirs to prevent any delimiter ambiguity
  dir = base64(str:dir);
  if (isnull(installs[ver])) installs[ver] = dir;
  else installs[ver] += DIR_SEPARATOR + dir;

  return installs;
}


# get_install_report
#
# Generates a report of all installs detected.  This report can be used
# directly in plugin output.
#
# args (* = required):
#  *display_name - name of the web application being reported on
#   installs     - installs to report. this should be an array with the same
#                  format that add_install() returns
#  *port         - port number the app was detected on
#   item         - page in each install directory where the app was detected.
#                  '/' by default.
#
# returns a report of installs detected, if any were detected, or
#         NULL otherwise
#
function get_install_report(display_name, installs, port, item)
{
  local_var info, version, n, dir, dirs, url, report;

  # Return if a required arg wasn't given
  if (isnull(display_name) || isnull(port)) return NULL;

  # Bail out if there's nothing to report (i.e. nothing was detected)
  if (isnull(installs) || max_index(keys(installs)) == 0) return NULL;

  if (isnull(item)) item = '/';

  info = "";
  n = 0;

  foreach version (sort(keys(installs)))
  {
    info += '\n  Version : ' + version + '\n';
    dirs = split(installs[version], sep:DIR_SEPARATOR, keep:FALSE);

    foreach dir (sort(dirs))
    {
      dir = base64_decode(str:dir);
      if (dir == '/') url = item;
      else url = dir + item;

      info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
      n++;
    }
  }

  report = '\nThe following instance';
  if (n == 1) report += ' of ' + display_name + ' was';
  else report += 's of ' + display_name + ' were';
  report += ' detected on the remote host :\n' + info;

  return report;
}


#
# get_vuln_report
#
# Generates a vulnerability report.  This report can be used directly in
# plugin output.
#
# args (* = required):
#   header  - report header. if this arg is omitted, DEFAULT_HEADER is used
#   trailer - report trailer
#  *items   - list of items that demonstrate the vulnerability. this can either
#             be a string (if there is only one item), or a list of strings
#  *port    - port the web application is being hosted on
#
# returns a vulnerability report, or
#         NULL if there were any errors generating the report
#
function get_vuln_report(header, trailer, items, port)
{
  local_var report, item;

  if (isnull(items) || isnull(port)) return NULL;

  items = make_list(items);
  if (max_index(items) == 0) return NULL;
  
  if (isnull(header))
  {
    header = DEFAULT_HEADER;
    if (max_index(items) > 1) header += 's';
  }

  report = string("\n", header, " :\n");

  foreach item (items)
    report += string("\n  ", build_url(qs:item, port:port), "\n");

  if (!isnull(trailer))
    report += string("\n", trailer, "\n");

  return report;
}


# get_install_from_kb
#
# Gets a web app install from the KB.  This function will fork if multiple
# installations of the same web app are read from the KB.
#
# args (both are required):
#   appname - name of the app, as it was stored in the KB (by add_install())
#   port    - port the app was detected on
#
# returns:
#   an array if the application was found in the KB:
#     ret['ver'] - detected version
#     ret['dir'] - web dir where the app is installed
#   NULL otherwise
#
function get_install_from_kb(appname, port)
{
  local_var install, match, dir, ver, ret;

  if (isnull(appname) || isnull(port)) return NULL;

  ret = NULL;
  install = get_kb_item('www/' + port + '/' + appname);
  if (isnull(install)) return NULL;

  match = eregmatch(string:install, pattern:'(.+) under (/.*)$');

  if (match)
  {
    # Strip the trailing slash from the dir, if it has one
    dir = ereg_replace(string:match[2], pattern:'^(/.*)/$', replace:"\1");
    if (dir == '/') dir = '';
    ver = match[1];
    ret = make_array(
      'ver', ver,
      'dir', dir
    );
  }

  return ret;
}

