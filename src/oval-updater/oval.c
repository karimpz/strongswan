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

#include "oval.h"

typedef struct private_oval_t private_oval_t;
typedef struct criterion_t criterion_t;

/**
 * Private data of an oval_t object.
 *
 */
struct private_oval_t {
	/**
	 * Public oval_t interface.
	 */
	oval_t public;

	/**
	 * CVE ID
	 */
	char *cve;

	/**
	 * Description
	 */
	char *description;

	/**
	 * List of criteria
	 */
	linked_list_t *criteria;

	/**
	  * Complete criterion consiting of object name and state */
	bool complete;
};

/**
 * This object defines an OVAL logical statement
 */
struct criterion_t {
	/** Test reference */
	char *tst_ref;
	/** State reference */
	char *ste_ref;
	/** Object reference */
	char *obj_ref;
	/** Object name */
	char *obj_name;
	/** Package version comparison operation */
	char *op;
	/** Package version */
	char *version;
	/** Complete criterion */
	bool complete;
};

METHOD(oval_t, add_criterion, void,
	private_oval_t *this, char *tst, char *ste, char *obj, char *obj_name,
	char *op, char *version)
{
	criterion_t *criterion;

	INIT(criterion,
		.tst_ref = tst,
		.ste_ref = ste,
		.obj_ref = obj,
		.obj_name = obj_name,
		.op = op,
		.version = version,
		.complete = tst && ste && obj && obj_name && op && version &&
					!streq(version, "0:0"),
	)

	if (criterion->complete)
	{
		this->complete = TRUE;
	}
	this->criteria->insert_last(this->criteria, criterion);
}

METHOD(oval_t, is_complete, bool,
	private_oval_t *this)
{
	return this->complete;
}

void print_metadata(private_oval_t *this, int level)
{
	if (this->cve)
	{
		if (level == 2)
		{
			DBG2(DBG_LIB, "%s", this->cve);
		}
		else
		{
			DBG3(DBG_LIB, "%s", this->cve);
		}
	}

	if (this->description)
	{
		const int max_char = 150;
		char line[max_char + 1];

		/* truncate description to max_char characters */
		if (strlen(this->description) > max_char)
		{
			strncpy(line, this->description, max_char);
			line[max_char] = '\0';
			if (level == 2)
			{
				DBG2(DBG_LIB, "  %s...", line);
			}
			else
			{
				DBG3(DBG_LIB, "  %s...", line);
			}
		}
		else
		{
			if (level == 2)
			{
				DBG2(DBG_LIB, "  %s", this->description);
			}
			else
			{
				DBG3(DBG_LIB, "  %s", this->description);
			}
		}
	}
}

METHOD(oval_t, print, void,
	private_oval_t *this)
{
	enumerator_t *enumerator;
	criterion_t *criterion;

	print_metadata(this, this->complete ? 2 : 3);

	enumerator = this->criteria->create_enumerator(this->criteria);
	while (enumerator->enumerate(enumerator, &criterion))
	{
		if (criterion->complete)
		{
			DBG2(DBG_LIB, "  %s", criterion->tst_ref);
			DBG2(DBG_LIB, "    %s", criterion->obj_ref);
			DBG2(DBG_LIB, "      %s", criterion->obj_name);
			DBG2(DBG_LIB, "    %s", criterion->ste_ref);
			DBG2(DBG_LIB, "      %s '%s'", criterion->op, criterion->version);
		}
		else
		{
			DBG3(DBG_LIB, "  %s", criterion->tst_ref);
			if (criterion->obj_ref)
			{
				DBG3(DBG_LIB, "    %s", criterion->obj_ref);
				if (criterion->obj_name)
				{
					DBG3(DBG_LIB, "      %s", criterion->obj_name);
				}
			}
			if (criterion->ste_ref)
			{
				DBG3(DBG_LIB, "    %s", criterion->ste_ref);
				if (criterion->version)
				{
					DBG3(DBG_LIB, "      %s '%s'", criterion->op,
												   criterion->version);
				}
			}
		}
	}
	enumerator->destroy(enumerator);
}

METHOD(oval_t, destroy, void,
	private_oval_t *this)
{
	this->criteria->destroy_function(this->criteria, (void*)free);
	free(this);
}

/**
 * See header
 */
oval_t* oval_create(char *cve, char *description)
{
	private_oval_t *this;

	INIT(this,
		.public = {
			.add_criterion = _add_criterion,
			.is_complete = _is_complete,
			.print = _print,
			.destroy = _destroy,
		},
		.cve = cve,
		.description = description,
		.criteria = linked_list_create(),
	)

	return &this->public;
}
