/*
 * Copyright (C) 2018 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>

#include <library.h>
#include <utils/debug.h>
#include <collections/hashtable.h>

#include <libxml/parser.h>

#include "oval.h"

/**
 * global debug output variables
 */
static int debug_level = 1;
static bool stderr_quiet = FALSE;

/**
 * oval_updater dbg function
 */
static void oval_updater_dbg(debug_t group, level_t level, char *fmt, ...)
{
	int priority = LOG_INFO;
	char buffer[8192];
	char *current = buffer, *next;
	va_list args;

	if (level <= debug_level)
	{
		if (!stderr_quiet)
		{
			va_start(args, fmt);
			vfprintf(stderr, fmt, args);
			fprintf(stderr, "\n");
			va_end(args);
		}

		/* write in memory buffer first */
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);

		/* do a syslog with every line */
		while (current)
		{
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			syslog(priority, "%s\n", current);
			current = next;
		}
	}
}

/**
 * atexit handler to close everything on shutdown
 */
static void cleanup(void)
{
	closelog();
	library_deinit();
}

static void usage(void)
{
	printf("\
Usage:\n\
  oval-updater --help\n\
  oval-updater [--debug <level>] [--quiet]  --os <string>\n\
               --uri <uri> --file <filename>\n\n\
  Options:\n\
    --help             print usage information\n\
    --debug <level>    set debug level\n\
    --quiet            suppress debug output to stderr\n\
    --os <string>      operating system\n\
     --file <filename> oval definition file\n\
    --uri <uri>        uri where to download deb package from\n");
 }

/**
 * global hashtables
 */
hashtable_t *tests, *objects, *states;

static void extract_criteria(oval_t *oval, xmlNodePtr node)
{
	xmlNodePtr cur, c, tst, ste, s;

	for (c = node->xmlChildrenNode; c != NULL; c = c->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(c))
		{
			continue;
		}
		if (!xmlStrcmp(c->name, "criterion"))
		{
			char *test_ref = NULL, *object_ref = NULL, *state_ref = NULL;
			char *object_name = NULL, *op = NULL, *version = NULL;

			test_ref = xmlGetProp(c, "test_ref");

			tst = tests->get(tests, test_ref);
			if (tst)
			{
				for (cur = tst->xmlChildrenNode; cur != NULL; cur = cur->next)
				{
					/* ignore empty or blank nodes */
					if (xmlIsBlankNode(cur))
					{
						continue;
					}
					if (!xmlStrcmp(cur->name, "object"))
					{
						object_ref = xmlGetProp(cur, "object_ref");
						object_name = objects->get(objects, object_ref);
					}
					else if (!xmlStrcmp(cur->name, "state"))
					{
						state_ref = xmlGetProp(cur, "state_ref");

						ste = states->get(states, state_ref);
						if (ste)
						{
							for (s = ste->xmlChildrenNode; s != NULL; s = s->next)
							{
								if (!xmlStrcmp(s->name, "evr"))
								{
									op = xmlGetProp(s, "operation");
									version = xmlNodeGetContent(s);
								}
							}
						}
					}
				}
			}
			oval->add_criterion(oval, test_ref, state_ref, object_ref,
								object_name, op, version);
		}
		else if (!xmlStrcmp(c->name, "criteria"))
		{
			extract_criteria(oval, c);
		}
	}
}

/**
 * Process an OVAL definition file
 */
static int process_oval_file(char *path, char *os, char *uri)
{
	xmlDocPtr doc;
	xmlNodePtr defs = NULL, objs = NULL, tsts = NULL, stes = NULL;
	xmlNodePtr cur, def, tst, obj, ste, c;
	oval_t *oval = NULL;
	char *cve_ref, *description, *title;
	uint32_t def_count = 0, tst_count = 0, obj_count = 0, ste_count = 0;
	uint32_t complete_count = 0;
	int result = EXIT_FAILURE;

    xmlInitParser();

	/* parsing OVAL XML file */
	doc = xmlReadFile(path, NULL, 0);
	if (!doc)
	{
		DBG1(DBG_LIB, "  could not be parsed \"%s\"", path);
		goto end;
	}

	/* check out the XML document */
	cur = xmlDocGetRootElement(doc);
	if (!cur)
	{
		DBG1(DBG_LIB, "  empty OVAL document");
		goto end;
	}
	if (xmlStrcmp(cur->name, "oval_definitions"))
	{
		DBG1(DBG_LIB, "  no oval_definitions element found");
		goto end;
	}

	/* Now walk the tree, handling nodes as we go */
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(cur))
		{
			continue;
		}
		if (!xmlStrcmp(cur->name, "definitions"))
		{
			defs = cur;
		}
		else if (!xmlStrcmp(cur->name, "objects"))
		{
			objs = cur;
		}
		else if(!xmlStrcmp(cur->name, "tests"))
		{
			tsts = cur;
		}
		else if (!xmlStrcmp(cur->name, "states"))
		{
			stes = cur;
		}
	}

	if (!defs || !objs || !tsts || !stes)
	{
		if (!defs)
		{
			DBG1(DBG_LIB, "  no definitions element found");
		}
		if (!objs)
		{
			DBG1(DBG_LIB, "  no objects element found");
		}
		if (!tsts)
		{
			DBG1(DBG_LIB, "  no tests element found");
		}
		if (!stes)
		{
			DBG1(DBG_LIB, "  no states element found");
		}
		goto end;
	}

	/* create tests hash table for fast access */
	tests = hashtable_create(hashtable_hash_str, hashtable_equals_str, 32768);

	/* enumerate tests */
	for (tst = tsts->xmlChildrenNode; tst != NULL; tst = tst->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(tst))
		{
			continue;
		}
		if (!xmlStrcmp(tst->name, "dpkginfo_test"))
		{
			tests->put(tests, xmlGetProp(tst, "id"), tst);
			tst_count++;
		}
	}
	DBG1(DBG_LIB, "%u tests", tst_count);

	/* create objects hash table for fast access */
	objects = hashtable_create(hashtable_hash_str, hashtable_equals_str, 4096);

	/* enumerate objects */
	for (obj = objs->xmlChildrenNode; obj != NULL; obj = obj->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(obj))
		{
			continue;
		}
		if (!xmlStrcmp(obj->name, "dpkginfo_object"))
		{
			for (cur = obj->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				/* ignore empty or blank nodes */
				if (xmlIsBlankNode(cur))
				{
					continue;
				}
				if (!xmlStrcmp(cur->name, "name"))
				{
					objects->put(objects, xmlGetProp(obj, "id"),
										  xmlNodeGetContent(cur));
					obj_count++;
				}
			}
		}
	}
	DBG1(DBG_LIB, "%u objects", obj_count);

	/* create states hash table for fast access */
	states = hashtable_create(hashtable_hash_str, hashtable_equals_str, 4096);

	/* enumerate states */
	for (ste = stes->xmlChildrenNode; ste != NULL; ste = ste->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(ste))
		{
			continue;
		}
		if (!xmlStrcmp(ste->name, "dpkginfo_state"))
		{
			states->put(states, xmlGetProp(ste, "id"), ste);
			ste_count++;
		}
	}
	DBG1(DBG_LIB, "%u states", ste_count);

	/* enumerate definitions */
	for (def = defs->xmlChildrenNode; def != NULL; def = def->next)
	{
		/* ignore empty or blank nodes */
		if (xmlIsBlankNode(def))
		{
			continue;
		}
		if (!xmlStrcmp(def->name, "definition") &&
			!xmlStrcmp(xmlGetProp(def, "class"), "vulnerability"))
		{
			cve_ref = description = title = NULL;

			for (cur = def->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				/* ignore empty or blank nodes */
				if (xmlIsBlankNode(cur))
				{
					continue;
				}
				if (!xmlStrcmp(cur->name, "metadata"))
				{
					for (c = cur->xmlChildrenNode; c != NULL; c = c->next)
					{
						/* ignore empty or blank nodes */
						if (xmlIsBlankNode(c))
						{
							continue;
						}
						if (!xmlStrcmp(c->name, "reference"))
						{
							cve_ref = xmlGetProp(c, "ref_id");
						}
						else if (!xmlStrcmp(c->name, "description"))
						{
							description = xmlNodeGetContent(c);
						}
						else if (!xmlStrcmp(c->name, "title"))
						{
							title = xmlNodeGetContent(c);
						}
					}
					if (cve_ref || title)
					{
						if (!cve_ref)
						{
							cve_ref = title;
						}
						def_count++;
					}
					oval = oval_create(cve_ref, description);
				}
				else if (!xmlStrcmp(cur->name, "criteria"))
				{
					extract_criteria(oval, cur);
				}
			}
		}
		if (oval)
		{
			if (oval->is_complete(oval))
			{
				complete_count++;
			}
			oval->print(oval);
			oval->destroy(oval);
			oval = NULL;
		}
	}
	DBG1(DBG_LIB, "%u of %u definitions are complete", complete_count, def_count);

	tests->destroy(tests);
	objects->destroy(objects);
	states->destroy(states);
	xmlFreeDoc(doc);
	result = EXIT_SUCCESS;

end:
	xmlCleanupParser();
	return result;
}

static int do_args(int argc, char *argv[])
{
	char *filename = NULL, *os = NULL, *uri = NULL;

	/* reinit getopt state */
	optind = 0;

	while (TRUE)
	{
		int c;

		struct option long_opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ "debug", required_argument, NULL, 'd' },
			{ "file", required_argument, NULL, 'f' },
			{ "os", required_argument, NULL, 'o' },
			{ "quiet", no_argument, NULL, 'q' },
			{ "uri", required_argument, NULL, 'u' },
			{ 0,0,0,0 }
		};

		c = getopt_long(argc, argv, "hd:f:o:qu:", long_opts, NULL);
		switch (c)
		{
			case EOF:
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'd':
				debug_level = atoi(optarg);
				continue;
			case 'f':
				filename = optarg;
				continue;
			case 'o':
				os = optarg;
				continue;
			case 'q':
				stderr_quiet = TRUE;
				continue;
			case 'u':
				uri = optarg;
				continue;
		}
		break;
	}

	if (filename && os && uri)
	{
		return process_oval_file(filename, os, uri);
	}
	else
	{
		usage();
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char *argv[])
{
	/* enable attest debugging hook */
	dbg = oval_updater_dbg;
	openlog("oval-updater", 0, LOG_DEBUG);

	atexit(cleanup);

	/* initialize library */
	if (!library_init(NULL, "oval-updater"))
	{
		exit(SS_RC_LIBSTRONGSWAN_INTEGRITY);
	}
	if (!lib->plugins->load(lib->plugins,
			lib->settings->get_str(lib->settings, "oval-updater.load",
												  "sqlite curl")))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	exit(do_args(argc, argv));
}
