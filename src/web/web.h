#define PLUGIN_NAME "WEB"

#ifndef __WEB_H
#define __WEB_H
#endif

#if (!defined __WEB_C)
#define EXT extern
#else
#define EXT
#endif

EXT void nfacctd_web_wrapper();
