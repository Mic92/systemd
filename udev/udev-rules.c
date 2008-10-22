/*
 * Copyright (C) 2008 Kay Sievers <kay.sievers@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>

#include "udev.h"

#define PREALLOC_TOKEN			2048
#define PREALLOC_STRBUF			32 * 1024

enum key_operation {
	KEY_OP_UNSET,
	KEY_OP_MATCH,
	KEY_OP_NOMATCH,
	KEY_OP_ADD,
	KEY_OP_ASSIGN,
	KEY_OP_ASSIGN_FINAL,
};

static const char *operation_str[] = {
	[KEY_OP_MATCH] =	"match",
	[KEY_OP_NOMATCH] =	"nomatch",
	[KEY_OP_ADD] =		"add",
	[KEY_OP_ASSIGN] =	"assign",
	[KEY_OP_ASSIGN_FINAL] =	"assign-final",
};

enum token_type {
	TK_UNDEF,
	TK_RULE,

	TK_M_WAITFOR,			/* val */
	TK_M_ACTION,			/* val */
	TK_M_DEVPATH,			/* val */
	TK_M_KERNEL,			/* val */
	TK_M_DEVLINK,			/* val */
	TK_M_NAME,			/* val */
	TK_M_ENV,			/* val, attr */
	TK_M_SUBSYSTEM,			/* val */
	TK_M_DRIVER,			/* val */
	TK_M_ATTR,			/* val, attr */

	TK_M_KERNELS,			/* val */
	TK_M_SUBSYSTEMS,		/* val */
	TK_M_DRIVERS,			/* val */
	TK_M_ATTRS,			/* val, attr */
	TK_PARENTS_MAX,

	TK_M_TEST,			/* val, mode_t */
	TK_M_PROGRAM,			/* val */
	TK_M_IMPORT_FILE,		/* val */
	TK_M_IMPORT_PROG,		/* val */
	TK_M_IMPORT_PARENT,		/* val */
	TK_M_RESULT,			/* val */

	TK_A_IGNORE_DEVICE,
	TK_A_STRING_ESCAPE_NONE,
	TK_A_STRING_ESCAPE_REPLACE,
	TK_A_NUM_FAKE_PART,		/* int */
	TK_A_DEVLINK_PRIO,		/* int */
	TK_A_OWNER,			/* val */
	TK_A_GROUP,			/* val */
	TK_A_MODE,			/* val */
	TK_A_OWNER_ID,			/* uid_t */
	TK_A_GROUP_ID,			/* gid_t */
	TK_A_MODE_ID,			/* mode_t */
	TK_A_ENV,			/* val, attr */
	TK_A_NAME,			/* val */
	TK_A_DEVLINK,			/* val */
	TK_A_EVENT_TIMEOUT,		/* int */
	TK_A_IGNORE_REMOVE,
	TK_A_ATTR,			/* val, attr */
	TK_A_RUN,			/* val, bool */
	TK_A_GOTO,			/* size_t */
	TK_A_LAST_RULE,

	TK_END,
};

static const char *token_str[] = {
	[TK_UNDEF] =			"UNDEF",
	[TK_RULE] =			"RULE",

	[TK_M_WAITFOR] =		"M WAITFOR",
	[TK_M_ACTION] =			"M ACTION",
	[TK_M_DEVPATH] =		"M DEVPATH",
	[TK_M_KERNEL] =			"M KERNEL",
	[TK_M_DEVLINK] =		"M DEVLINK",
	[TK_M_NAME] =			"M NAME",
	[TK_M_ENV] =			"M ENV",
	[TK_M_SUBSYSTEM] =		"M SUBSYSTEM",
	[TK_M_DRIVER] =			"M DRIVER",
	[TK_M_ATTR] =			"M ATTR",

	[TK_M_KERNELS] =		"M KERNELS",
	[TK_M_SUBSYSTEMS] =		"M SUBSYSTEMS",
	[TK_M_DRIVERS] =		"M DRIVERS",
	[TK_M_ATTRS] =			"M ATTRS",
	[TK_PARENTS_MAX] =		"PARENTS_MAX",

	[TK_M_TEST] =			"M TEST",
	[TK_M_PROGRAM] =		"M PROGRAM",
	[TK_M_IMPORT_FILE] =		"M IMPORT_FILE",
	[TK_M_IMPORT_PROG] =		"M IMPORT_PROG",
	[TK_M_IMPORT_PARENT] =		"M MPORT_PARENT",
	[TK_M_RESULT] =			"M RESULT",

	[TK_A_IGNORE_DEVICE] =		"A IGNORE_DEVICE",
	[TK_A_STRING_ESCAPE_NONE] =	"A STRING_ESCAPE_NONE",
	[TK_A_STRING_ESCAPE_REPLACE] =	"A STRING_ESCAPE_REPLACE",
	[TK_A_NUM_FAKE_PART] =		"A NUM_FAKE_PART",
	[TK_A_DEVLINK_PRIO] =		"A DEVLINK_PRIO",
	[TK_A_OWNER] =			"A OWNER",
	[TK_A_GROUP] =			"A GROUP",
	[TK_A_MODE] =			"A MODE",
	[TK_A_OWNER_ID] =		"A OWNER_ID",
	[TK_A_GROUP_ID] =		"A GROUP_ID",
	[TK_A_MODE_ID] =		"A MODE_ID",
	[TK_A_ENV] =			"A ENV",
	[TK_A_NAME] =			"A NAME",
	[TK_A_DEVLINK] =		"A DEVLINK",
	[TK_A_EVENT_TIMEOUT] =		"A EVENT_TIMEOUT",
	[TK_A_IGNORE_REMOVE] =		"A IGNORE_REMOVE",
	[TK_A_ATTR] =			"A ATTR",
	[TK_A_RUN] =			"A RUN",
	[TK_A_GOTO] =			"A GOTO",
	[TK_A_LAST_RULE] =		"A LAST_RULE",

	[TK_END] =			"END",
};

struct token {
	enum token_type type;
	union {
		struct {
			unsigned int next_rule;
			unsigned int label_off;
			unsigned int filename_off;
		} rule;
		struct {
			enum key_operation op;
			unsigned int value_off;
			union {
				unsigned int attr_off;
				int ignore_error;
				int i;
				unsigned int rule_goto;
				mode_t  mode;
				uid_t uid;
				gid_t gid;
				int num_fake_part;
				int devlink_prio;
				int event_timeout;
			};
		} key;
	};
};

#define MAX_TK		64
struct rule_tmp {
	struct udev_rules *rules;
	struct token rule;
	struct token token[MAX_TK];
	unsigned int token_cur;
};

struct udev_rules {
	struct udev *udev;
	int resolve_names;
	struct token *tokens;
	unsigned int token_cur;
	unsigned int token_max;
	char *buf;
	size_t buf_cur;
	size_t buf_max;
	unsigned int buf_count;
};

/* we could lookup and return existing strings, or tails of strings */
static int add_string(struct udev_rules *rules, const char *str)
{
	size_t len = strlen(str)+1;
	int off;

	if (rules->buf_cur + len+1 >= rules->buf_max) {
		char *buf;
		unsigned int add;

		/* double the buffer size */
		add = rules->buf_max;
		if (add < len)
			add = len;

		buf = realloc(rules->buf, rules->buf_max + add);
		if (buf == NULL)
			return -1;
		info(rules->udev, "extend buffer from %zu to %zu\n", rules->buf_max, rules->buf_max + add);
		rules->buf = buf;
		rules->buf_max += add;
	}
	off = rules->buf_cur;
	memcpy(&rules->buf[rules->buf_cur], str, len);
	rules->buf_cur += len;
	rules->buf_count++;
	return off;
}

static int add_token(struct udev_rules *rules, struct token *token)
{

	if (rules->token_cur+1 >= rules->token_max) {
		struct token *tokens;
		unsigned int add;

		/* double the buffer size */
		add = rules->token_max;
		if (add < 1)
			add = 1;

		tokens = realloc(rules->tokens, (rules->token_max + add ) * sizeof(struct token));
		if (tokens == NULL)
			return -1;
		info(rules->udev, "extend tokens from %u to %u\n", rules->token_max, rules->token_max + add);
		rules->tokens = tokens;
		rules->token_max += add;
	}
	memcpy(&rules->tokens[rules->token_cur], token, sizeof(struct token));
	rules->token_cur++;
	return 0;
}

static int import_property_from_string(struct udev_device *dev, char *line)
{
	struct udev *udev = udev_device_get_udev(dev);
	char *key;
	char *val;
	size_t len;

	/* find key */
	key = line;
	while (isspace(key[0]))
		key++;

	/* comment or empty line */
	if (key[0] == '#' || key[0] == '\0')
		return -1;

	/* split key/value */
	val = strchr(key, '=');
	if (val == NULL)
		return -1;
	val[0] = '\0';
	val++;

	/* find value */
	while (isspace(val[0]))
		val++;

	/* terminate key */
	len = strlen(key);
	if (len == 0)
		return -1;
	while (isspace(key[len-1]))
		len--;
	key[len] = '\0';

	/* terminate value */
	len = strlen(val);
	if (len == 0)
		return -1;
	while (isspace(val[len-1]))
		len--;
	val[len] = '\0';

	if (len == 0)
		return -1;

	/* unquote */
	if (val[0] == '"' || val[0] == '\'') {
		if (val[len-1] != val[0]) {
			info(udev, "inconsistent quoting: '%s', skip\n", line);
			return -1;
		}
		val[len-1] = '\0';
		val++;
	}

	info(udev, "adding '%s'='%s'\n", key, val);

	/* handle device, renamed by external tool, returning new path */
	if (strcmp(key, "DEVPATH") == 0) {
		char syspath[UTIL_PATH_SIZE];

		info(udev, "updating devpath from '%s' to '%s'\n",
		     udev_device_get_devpath(dev), val);
		util_strlcpy(syspath, udev_get_sys_path(udev), sizeof(syspath));
		util_strlcat(syspath, val, sizeof(syspath));
		udev_device_set_syspath(dev, syspath);
	} else {
		struct udev_list_entry *entry;

		entry = udev_device_add_property(dev, key, val);
		/* store in db */
		udev_list_entry_set_flag(entry, 1);
	}
	return 0;
}

static int import_file_into_properties(struct udev_device *dev, const char *filename)
{
	FILE *f;
	char line[UTIL_LINE_SIZE];

	f = fopen(filename, "r");
	if (f == NULL)
		return -1;
	while (fgets(line, sizeof(line), f) != NULL)
		import_property_from_string(dev, line);
	fclose(f);
	return 0;
}

static int import_program_into_properties(struct udev_device *dev, const char *program)
{
	struct udev *udev = udev_device_get_udev(dev);
	char **envp;
	char result[2048];
	size_t reslen;
	char *line;

	envp = udev_device_get_properties_envp(dev);
	if (util_run_program(udev, program, envp, result, sizeof(result), &reslen) != 0)
		return -1;

	line = result;
	while (line != NULL) {
		char *pos;

		pos = strchr(line, '\n');
		if (pos != NULL) {
			pos[0] = '\0';
			pos = &pos[1];
		}
		import_property_from_string(dev, line);
		line = pos;
	}
	return 0;
}

static int import_parent_into_properties(struct udev_device *dev, const char *filter)
{
	struct udev *udev = udev_device_get_udev(dev);
	struct udev_device *dev_parent;
	struct udev_list_entry *list_entry;

	dev_parent = udev_device_get_parent(dev);
	if (dev_parent == NULL)
		return -1;

	dbg(udev, "found parent '%s', get the node name\n", udev_device_get_syspath(dev_parent));
	udev_list_entry_foreach(list_entry, udev_device_get_properties_list_entry(dev_parent)) {
		const char *key = udev_list_entry_get_name(list_entry);
		const char *val = udev_list_entry_get_value(list_entry);

		if (fnmatch(filter, key, 0) == 0) {
			struct udev_list_entry *entry;

			dbg(udev, "import key '%s=%s'\n", key, val);
			entry = udev_device_add_property(dev, key, val);
			/* store in db */
			udev_list_entry_set_flag(entry, 1);
		}
	}
	return 0;
}

#define WAIT_LOOP_PER_SECOND		50
static int wait_for_file(struct udev_device *dev, const char *file, int timeout)
{
	struct udev *udev = udev_device_get_udev(dev);
	char filepath[UTIL_PATH_SIZE];
	char devicepath[UTIL_PATH_SIZE] = "";
	struct stat stats;
	int loop = timeout * WAIT_LOOP_PER_SECOND;

	/* a relative path is a device attribute */
	if (file[0] != '/') {
		util_strlcpy(devicepath, udev_get_sys_path(udev), sizeof(devicepath));
		util_strlcat(devicepath, udev_device_get_devpath(dev), sizeof(devicepath));

		util_strlcpy(filepath, devicepath, sizeof(filepath));
		util_strlcat(filepath, "/", sizeof(filepath));
		util_strlcat(filepath, file, sizeof(filepath));
		file = filepath;
	}

	dbg(udev, "will wait %i sec for '%s'\n", timeout, file);
	while (--loop) {
		/* lookup file */
		if (stat(file, &stats) == 0) {
			info(udev, "file '%s' appeared after %i loops\n", file, (timeout * WAIT_LOOP_PER_SECOND) - loop-1);
			return 0;
		}
		/* make sure, the device did not disappear in the meantime */
		if (devicepath[0] != '\0' && stat(devicepath, &stats) != 0) {
			info(udev, "device disappeared while waiting for '%s'\n", file);
			return -2;
		}
		info(udev, "wait for '%s' for %i mseconds\n", file, 1000 / WAIT_LOOP_PER_SECOND);
		usleep(1000 * 1000 / WAIT_LOOP_PER_SECOND);
	}
	info(udev, "waiting for '%s' failed\n", file);
	return -1;
}

static int attr_subst_subdir(char *attr, size_t len)
{
	char *pos;
	int found = 0;

	pos = strstr(attr, "/*/");
	if (pos != NULL) {
		char str[UTIL_PATH_SIZE];
		DIR *dir;

		pos[1] = '\0';
		util_strlcpy(str, &pos[2], sizeof(str));
		dir = opendir(attr);
		if (dir != NULL) {
			struct dirent *dent;

			for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
				struct stat stats;

				if (dent->d_name[0] == '.')
					continue;
				util_strlcat(attr, dent->d_name, len);
				util_strlcat(attr, str, len);
				if (stat(attr, &stats) == 0) {
					found = 1;
					break;
				}
				pos[1] = '\0';
			}
			closedir(dir);
		}
		if (!found)
			util_strlcat(attr, str, len);
	}

	return found;
}

static int get_key(struct udev *udev, char **line, char **key, enum key_operation *op, char **value)
{
	char *linepos;
	char *temp;

	linepos = *line;
	if (linepos == NULL && linepos[0] == '\0')
		return -1;

	/* skip whitespace */
	while (isspace(linepos[0]) || linepos[0] == ',')
		linepos++;

	/* get the key */
	if (linepos[0] == '\0')
		return -1;
	*key = linepos;

	while (1) {
		linepos++;
		if (linepos[0] == '\0')
			return -1;
		if (isspace(linepos[0]))
			break;
		if (linepos[0] == '=')
			break;
		if ((linepos[0] == '+') || (linepos[0] == '!') || (linepos[0] == ':'))
			if (linepos[1] == '=')
				break;
	}

	/* remember end of key */
	temp = linepos;

	/* skip whitespace after key */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* get operation type */
	if (linepos[0] == '=' && linepos[1] == '=') {
		*op = KEY_OP_MATCH;
		linepos += 2;
	} else if (linepos[0] == '!' && linepos[1] == '=') {
		*op = KEY_OP_NOMATCH;
		linepos += 2;
	} else if (linepos[0] == '+' && linepos[1] == '=') {
		*op = KEY_OP_ADD;
		linepos += 2;
	} else if (linepos[0] == '=') {
		*op = KEY_OP_ASSIGN;
		linepos++;
	} else if (linepos[0] == ':' && linepos[1] == '=') {
		*op = KEY_OP_ASSIGN_FINAL;
		linepos += 2;
	} else
		return -1;

	/* terminate key */
	temp[0] = '\0';

	/* skip whitespace after operator */
	while (isspace(linepos[0]))
		linepos++;
	if (linepos[0] == '\0')
		return -1;

	/* get the value*/
	if (linepos[0] == '"')
		linepos++;
	else
		return -1;
	*value = linepos;

	temp = strchr(linepos, '"');
	if (!temp)
		return -1;
	temp[0] = '\0';
	temp++;
	dbg(udev, "%s '%s'-'%s'\n", operation_str[*op], *key, *value);

	/* move line to next key */
	*line = temp;
	return 0;
}

/* extract possible KEY{attr} */
static char *get_key_attribute(struct udev *udev, char *str)
{
	char *pos;
	char *attr;

	attr = strchr(str, '{');
	if (attr != NULL) {
		attr++;
		pos = strchr(attr, '}');
		if (pos == NULL) {
			err(udev, "missing closing brace for format\n");
			return NULL;
		}
		pos[0] = '\0';
		dbg(udev, "attribute='%s'\n", attr);
		return attr;
	}
	return NULL;
}

static int rule_add_token(struct rule_tmp *rule_tmp, enum token_type type,
			  enum key_operation op,
			  const char *value, const void *data)
{
	struct token *token = &rule_tmp->token[rule_tmp->token_cur];
	const char *attr = data;
	mode_t mode = 0000;

	switch (type) {
	case TK_M_WAITFOR:
	case TK_M_ACTION:
	case TK_M_DEVPATH:
	case TK_M_KERNEL:
	case TK_M_SUBSYSTEM:
	case TK_M_DRIVER:
	case TK_M_DEVLINK:
	case TK_M_NAME:
	case TK_M_KERNELS:
	case TK_M_SUBSYSTEMS:
	case TK_M_DRIVERS:
	case TK_M_PROGRAM:
	case TK_M_IMPORT_FILE:
	case TK_M_IMPORT_PROG:
	case TK_M_IMPORT_PARENT:
	case TK_M_RESULT:
	case TK_A_OWNER:
	case TK_A_GROUP:
	case TK_A_MODE:
	case TK_A_NAME:
	case TK_A_DEVLINK:
	case TK_A_GOTO:
		token->key.value_off = add_string(rule_tmp->rules, value);
		break;
	case TK_M_ENV:
	case TK_M_ATTR:
	case TK_M_ATTRS:
	case TK_A_ATTR:
	case TK_A_ENV:
		token->key.value_off = add_string(rule_tmp->rules, value);
		token->key.attr_off = add_string(rule_tmp->rules, attr);
		break;
	case TK_M_TEST:
		if (data != NULL)
			mode = *(mode_t *)data;
		token->key.value_off = add_string(rule_tmp->rules, value);
		token->key.mode = mode;
		break;
	case TK_A_IGNORE_DEVICE:
	case TK_A_STRING_ESCAPE_NONE:
	case TK_A_STRING_ESCAPE_REPLACE:
	case TK_A_IGNORE_REMOVE:
	case TK_A_LAST_RULE:
		break;
	case TK_A_RUN:
		token->key.value_off = add_string(rule_tmp->rules, value);
		token->key.ignore_error = *(int *)data;
		break;
	case TK_A_NUM_FAKE_PART:
		token->key.num_fake_part = *(int *)data;
		break;
	case TK_A_DEVLINK_PRIO:
		token->key.devlink_prio = *(int *)data;
		break;
	case TK_A_OWNER_ID:
		token->key.uid = *(uid_t *)data;
		break;
	case TK_A_GROUP_ID:
		token->key.gid = *(gid_t *)data;
		break;
	case TK_A_MODE_ID:
		token->key.mode = *(mode_t *)data;
		break;
	case TK_A_EVENT_TIMEOUT:
		token->key.event_timeout = *(int *)data;
		break;
	case TK_RULE:
	case TK_PARENTS_MAX:
	case TK_END:
	case TK_UNDEF:
		err(rule_tmp->rules->udev, "wrong type %u\n", type);
		return -1;
	}
	token->type = type;
	token->key.op = op;
	rule_tmp->token_cur++;
	if (rule_tmp->token_cur >= ARRAY_SIZE(rule_tmp->token)) {
		err(rule_tmp->rules->udev, "temporary rule array too small\n");
		return -1;
	}
	return 0;
}

#ifdef DEBUG
static void dump_token(struct udev_rules *rules, struct token *token)
{
	enum token_type type = token->type;
	enum key_operation op = token->key.op;
	const char *value = &rules->buf[token->key.value_off];
	const char *attr = &rules->buf[token->key.attr_off];

	switch (type) {
	case TK_RULE:
		{
			const char *tks_ptr = (char *)rules->tokens;
			const char *tk_ptr = (char *)token;
			unsigned int off = tk_ptr - tks_ptr;

			dbg(rules->udev, "* RULE '%s', off: %u(%u), next: %u, label: '%s'\n",
			    &rules->buf[token->rule.filename_off],
			    off / (unsigned int) sizeof(struct token), off,
			    token->rule.next_rule,
			    &rules->buf[token->rule.label_off]);
			break;
		}
	case TK_M_WAITFOR:
	case TK_M_ACTION:
	case TK_M_DEVPATH:
	case TK_M_KERNEL:
	case TK_M_SUBSYSTEM:
	case TK_M_DRIVER:
	case TK_M_DEVLINK:
	case TK_M_NAME:
	case TK_M_KERNELS:
	case TK_M_SUBSYSTEMS:
	case TK_M_DRIVERS:
	case TK_M_PROGRAM:
	case TK_M_IMPORT_FILE:
	case TK_M_IMPORT_PROG:
	case TK_M_IMPORT_PARENT:
	case TK_M_RESULT:
	case TK_A_NAME:
	case TK_A_DEVLINK:
	case TK_A_OWNER:
	case TK_A_GROUP:
	case TK_A_MODE:
	case TK_A_RUN:
		dbg(rules->udev, "%s %s '%s'\n", token_str[type], operation_str[op], value);
		break;
	case TK_M_ATTR:
	case TK_M_ATTRS:
	case TK_M_ENV:
	case TK_A_ATTR:
	case TK_A_ENV:
		dbg(rules->udev, "%s %s '%s' '%s'\n", token_str[type], operation_str[op], attr, value);
		break;
	case TK_A_IGNORE_DEVICE:
	case TK_A_STRING_ESCAPE_NONE:
	case TK_A_STRING_ESCAPE_REPLACE:
	case TK_A_LAST_RULE:
	case TK_A_IGNORE_REMOVE:
		dbg(rules->udev, "%s\n", token_str[type]);
		break;
	case TK_M_TEST:
		dbg(rules->udev, "%s %s '%s' %#o\n", token_str[type], operation_str[op], value, token->key.mode);
		break;
	case TK_A_NUM_FAKE_PART:
		dbg(rules->udev, "%s %u\n", token_str[type], token->key.num_fake_part);
		break;
	case TK_A_DEVLINK_PRIO:
		dbg(rules->udev, "%s %s %u\n", token_str[type], operation_str[op], token->key.devlink_prio);
		break;
	case TK_A_OWNER_ID:
		dbg(rules->udev, "%s %s %u\n", token_str[type], operation_str[op], token->key.uid);
		break;
	case TK_A_GROUP_ID:
		dbg(rules->udev, "%s %s %u\n", token_str[type], operation_str[op], token->key.gid);
		break;
	case TK_A_MODE_ID:
		dbg(rules->udev, "%s %s %#o\n", token_str[type], operation_str[op], token->key.mode);
		break;
	case TK_A_EVENT_TIMEOUT:
		dbg(rules->udev, "%s %s %u\n", token_str[type], operation_str[op], token->key.event_timeout);
		break;
	case TK_A_GOTO:
		dbg(rules->udev, "%s '%s' %u\n", token_str[type], value, token->key.rule_goto);
		break;
	case TK_END:
		dbg(rules->udev, "* %s\n", token_str[type]);
		break;
	case TK_PARENTS_MAX:
	case TK_UNDEF:
		dbg(rules->udev, "unknown type %u\n", type);
		break;
	}
}

static void dump_rules(struct udev_rules *rules)
{
	unsigned int i;

	dbg(rules->udev, "dumping %u (%zu bytes) tokens, %u (%zu bytes) strings\n",
	    rules->token_cur,
	    rules->token_cur * sizeof(struct token),
	    rules->buf_count,
	    rules->buf_cur);
	for(i = 0; i < rules->token_cur; i++)
		dump_token(rules, &rules->tokens[i]);
}
#else
static inline void dump_token(struct udev_rules *rules, struct token *token) {}
static inline void dump_rules(struct udev_rules *rules) {}
#endif /* DEBUG */

static int sort_token(struct udev_rules *rules, struct rule_tmp *rule_tmp)
{
	unsigned int i;
	unsigned int start = 0;
	unsigned int end = rule_tmp->token_cur;

	for (i = 0; i < rule_tmp->token_cur; i++) {
		enum token_type next_val = TK_UNDEF;
		unsigned int next_idx;
		unsigned int j;

		/* find smallest value */
		for (j = start; j < end; j++) {
			if (rule_tmp->token[j].type == TK_UNDEF)
				continue;
			if (next_val == TK_UNDEF || rule_tmp->token[j].type < next_val) {
				next_val = rule_tmp->token[j].type;
				next_idx = j;
			}
		}

		/* add token and mark done */
		if (add_token(rules, &rule_tmp->token[next_idx]) != 0)
			return -1;
		rule_tmp->token[next_idx].type = TK_UNDEF;

		/* shrink range */
		if (next_idx == start)
			start++;
		if (next_idx+1 == end)
			end--;
	}
	return 0;
}

static int add_rule(struct udev_rules *rules, char *line,
		    const char *filename, unsigned int filename_off, unsigned int lineno)
{
	int valid = 0;
	char *linepos;
	char *attr;
	int physdev = 0;
	struct rule_tmp rule_tmp;

	memset(&rule_tmp, 0x00, sizeof(struct rule_tmp));
	rule_tmp.rules = rules;
	rule_tmp.rule.type = TK_RULE;
	rule_tmp.rule.rule.filename_off = filename_off;

	linepos = line;
	while (1) {
		char *key;
		char *value;
		enum key_operation op = KEY_OP_UNSET;

		if (get_key(rules->udev, &linepos, &key, &op, &value) != 0)
			break;

		if (strcasecmp(key, "ACTION") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid ACTION operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_ACTION, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DEVPATH") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DEVPATH operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_DEVPATH, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNEL") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid KERNEL operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_KERNEL, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEM") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid SUBSYSTEM operation\n");
				goto invalid;
			}
			/* bus, class, subsystem events should all be the same */
			if (strcmp(value, "subsystem") == 0 ||
			    strcmp(value, "bus") == 0 ||
			    strcmp(value, "class") == 0) {
				if (strcmp(value, "bus") == 0 || strcmp(value, "class") == 0)
					err(rules->udev, "'%s' must be specified as 'subsystem' \n"
					    "please fix it in %s:%u", value, filename, lineno);
				rule_add_token(&rule_tmp, TK_M_SUBSYSTEM, op, "subsystem|class|bus", NULL);
			} else
				rule_add_token(&rule_tmp, TK_M_SUBSYSTEM, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVER") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DRIVER operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_DRIVER, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTR{", sizeof("ATTR{")-1) == 0) {
			attr = get_key_attribute(rules->udev, key + sizeof("ATTR")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ATTR attribute\n");
				goto invalid;
			}
			if (op == KEY_OP_MATCH || op == KEY_OP_NOMATCH) {
				rule_add_token(&rule_tmp, TK_M_ATTR, op, value, attr);
			} else {
				rule_add_token(&rule_tmp, TK_A_ATTR, op, value, attr);
			}
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "KERNELS") == 0 ||
		    strcasecmp(key, "ID") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid KERNELS operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_KERNELS, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "SUBSYSTEMS") == 0 ||
		    strcasecmp(key, "BUS") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid SUBSYSTEMS operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_SUBSYSTEMS, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "DRIVERS") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid DRIVERS operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_DRIVERS, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ATTRS{", sizeof("ATTRS{")-1) == 0 ||
		    strncasecmp(key, "SYSFS{", sizeof("SYSFS{")-1) == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid ATTRS operation\n");
				goto invalid;
			}
			attr = get_key_attribute(rules->udev, key + sizeof("ATTRS")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ATTRS attribute\n");
				goto invalid;
			}
			if (strncmp(attr, "device/", 7) == 0)
				err(rules->udev, "the 'device' link may not be available in a future kernel, "
				    "please fix it in %s:%u", filename, lineno);
			else if (strstr(attr, "../") != NULL)
				err(rules->udev, "do not reference parent sysfs directories directly, "
				    "it may break with a future kernel, please fix it in %s:%u", filename, lineno);
			rule_add_token(&rule_tmp, TK_M_ATTRS, op, value, attr);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "ENV{", sizeof("ENV{")-1) == 0) {
			attr = get_key_attribute(rules->udev, key + sizeof("ENV")-1);
			if (attr == NULL) {
				err(rules->udev, "error parsing ENV attribute\n");
				goto invalid;
			}
			if (strncmp(attr, "PHYSDEV", 7) == 0)
				physdev = 1;
			if (op == KEY_OP_MATCH || op == KEY_OP_NOMATCH) {
				if (rule_add_token(&rule_tmp, TK_M_ENV, op, value, attr) != 0)
					goto invalid;
			} else {
				if (rule_add_token(&rule_tmp, TK_A_ENV, op, value, attr) != 0)
					goto invalid;
			}
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "PROGRAM") == 0) {
			rule_add_token(&rule_tmp, TK_M_PROGRAM, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "RESULT") == 0) {
			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid RESULT operation\n");
				goto invalid;
			}
			rule_add_token(&rule_tmp, TK_M_RESULT, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "IMPORT", sizeof("IMPORT")-1) == 0) {
			attr = get_key_attribute(rules->udev, key + sizeof("IMPORT")-1);
			if (attr != NULL && strstr(attr, "program")) {
				dbg(rules->udev, "IMPORT will be executed\n");
				rule_add_token(&rule_tmp, TK_M_IMPORT_PROG, op, value, NULL);
				valid = 1;
			} else if (attr != NULL && strstr(attr, "file")) {
				dbg(rules->udev, "IMPORT will be included as file\n");
				rule_add_token(&rule_tmp, TK_M_IMPORT_FILE, op, value, NULL);
				valid = 1;
			} else if (attr != NULL && strstr(attr, "parent")) {
				dbg(rules->udev, "IMPORT will include the parent values\n");
				rule_add_token(&rule_tmp, TK_M_IMPORT_PARENT, op, value, NULL);
				valid = 1;
			} else {
				/* figure it out if it is executable */
				char file[UTIL_PATH_SIZE];
				char *pos;
				struct stat statbuf;

				util_strlcpy(file, value, sizeof(file));
				pos = strchr(file, ' ');
				if (pos)
					pos[0] = '\0';

				/* allow programs in /lib/udev called without the path */
				if (strchr(file, '/') == NULL) {
					util_strlcpy(file, UDEV_PREFIX "/lib/udev/", sizeof(file));
					util_strlcat(file, value, sizeof(file));
					pos = strchr(file, ' ');
					if (pos)
						pos[0] = '\0';
				}

				dbg(rules->udev, "IMPORT auto mode for '%s'\n", file);
				if (!lstat(file, &statbuf) && (statbuf.st_mode & S_IXUSR)) {
					dbg(rules->udev, "IMPORT will be executed (autotype)\n");
					rule_add_token(&rule_tmp, TK_M_IMPORT_PROG, op, value, NULL);
					valid = 1;
				} else {
					dbg(rules->udev, "IMPORT will be included as file (autotype)\n");
					rule_add_token(&rule_tmp, TK_M_IMPORT_FILE, op, value, NULL);
					valid = 1;
				}
			}
			continue;
		}

		if (strncasecmp(key, "TEST", sizeof("TEST")-1) == 0) {
			mode_t mode = 0;

			if (op != KEY_OP_MATCH && op != KEY_OP_NOMATCH) {
				err(rules->udev, "invalid TEST operation\n");
				goto invalid;
			}
			attr = get_key_attribute(rules->udev, key + sizeof("TEST")-1);
			if (attr != NULL) {
				mode = strtol(attr, NULL, 8);
				rule_add_token(&rule_tmp, TK_M_TEST, op, value, &mode);
			} else {
				rule_add_token(&rule_tmp, TK_M_TEST, op, value, NULL);
			}
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "RUN", sizeof("RUN")-1) == 0) {
			int flag = 0;

			attr = get_key_attribute(rules->udev, key + sizeof("RUN")-1);
			if (attr != NULL && strstr(attr, "ignore_error"))
				flag = 1;
			rule_add_token(&rule_tmp, TK_A_RUN, op, value, &flag);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "WAIT_FOR") == 0 || strcasecmp(key, "WAIT_FOR_SYSFS") == 0) {
			rule_add_token(&rule_tmp, TK_M_WAITFOR, 0, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "LABEL") == 0) {
			rule_tmp.rule.rule.label_off = add_string(rules, value);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "GOTO") == 0) {
			rule_add_token(&rule_tmp, TK_A_GOTO, 0, value, NULL);
			valid = 1;
			continue;
		}

		if (strncasecmp(key, "NAME", sizeof("NAME")-1) == 0) {
			if (op == KEY_OP_MATCH || op == KEY_OP_NOMATCH) {
				rule_add_token(&rule_tmp, TK_M_NAME, op, value, NULL);
			} else {
				if (value[0] == '\0')
					dbg(rules->udev, "name empty, node creation suppressed\n");
				rule_add_token(&rule_tmp, TK_A_NAME, op, value, NULL);
				attr = get_key_attribute(rules->udev, key + sizeof("NAME")-1);
				if (attr != NULL) {
					if (strstr(attr, "all_partitions") != NULL) {
						int num = DEFAULT_FAKE_PARTITIONS_COUNT;

						dbg(rules->udev, "creation of partition nodes requested\n");
						rule_add_token(&rule_tmp, TK_A_NUM_FAKE_PART, 0, NULL, &num);
					}
					if (strstr(attr, "ignore_remove") != NULL) {
						dbg(rules->udev, "remove event should be ignored\n");
						rule_add_token(&rule_tmp, TK_A_IGNORE_REMOVE, 0, NULL, NULL);
					}
				}
			}
			continue;
		}

		if (strcasecmp(key, "SYMLINK") == 0) {
			if (op == KEY_OP_MATCH || op == KEY_OP_NOMATCH)
					rule_add_token(&rule_tmp, TK_M_DEVLINK, op, value, NULL);
				else
					rule_add_token(&rule_tmp, TK_A_DEVLINK, op, value, NULL);
				valid = 1;
				continue;
			}

		if (strcasecmp(key, "OWNER") == 0) {
			uid_t uid;
			char *endptr;

			uid = strtoul(value, &endptr, 10);
			if (endptr[0] == '\0') {
				rule_add_token(&rule_tmp, TK_A_OWNER_ID, op, NULL, &uid);
			} else if (rules->resolve_names && strchr("$%", value[0]) == NULL) {
				uid = util_lookup_user(rules->udev, value);
				rule_add_token(&rule_tmp, TK_A_OWNER_ID, op, NULL, &uid);
			} else {
				rule_add_token(&rule_tmp, TK_A_OWNER, op, value, NULL);
			}
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "GROUP") == 0) {
			gid_t gid;
			char *endptr;

			gid = strtoul(value, &endptr, 10);
			if (endptr[0] == '\0') {
				rule_add_token(&rule_tmp, TK_A_GROUP_ID, op, NULL, &gid);
			} else if (rules->resolve_names && strchr("$%", value[0]) == NULL) {
				gid = util_lookup_group(rules->udev, value);
				rule_add_token(&rule_tmp, TK_A_GROUP_ID, op, NULL, &gid);
			} else {
				rule_add_token(&rule_tmp, TK_A_GROUP, op, value, NULL);
			}
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "MODE") == 0) {
			mode_t mode;
			char *endptr;

			mode = strtol(value, &endptr, 8);
			if (endptr[0] == '\0')
				rule_add_token(&rule_tmp, TK_A_MODE_ID, op, NULL, &mode);
			else
				rule_add_token(&rule_tmp, TK_A_MODE, op, value, NULL);
			valid = 1;
			continue;
		}

		if (strcasecmp(key, "OPTIONS") == 0) {
			const char *pos;

			if (strstr(value, "last_rule") != NULL) {
				dbg(rules->udev, "last rule to be applied\n");
				rule_add_token(&rule_tmp, TK_A_LAST_RULE, 0, NULL, NULL);
			}
			if (strstr(value, "ignore_device") != NULL) {
				dbg(rules->udev, "device should be ignored\n");
				rule_add_token(&rule_tmp, TK_A_IGNORE_DEVICE, 0, NULL, NULL);
			}
			if (strstr(value, "ignore_remove") != NULL) {
				dbg(rules->udev, "remove event should be ignored\n");
				rule_add_token(&rule_tmp, TK_A_IGNORE_REMOVE, 0, NULL, NULL);
			}
			pos = strstr(value, "link_priority=");
			if (pos != NULL) {
				int prio = atoi(&pos[strlen("link_priority=")]);

				rule_add_token(&rule_tmp, TK_A_DEVLINK_PRIO, 0, NULL, &prio);
				dbg(rules->udev, "link priority=%i\n", prio);
			}
			pos = strstr(value, "event_timeout=");
			if (pos != NULL) {
				int tout = atoi(&pos[strlen("event_timeout=")]);

				rule_add_token(&rule_tmp, TK_A_EVENT_TIMEOUT, 0, NULL, &tout);
				dbg(rules->udev, "event timout=%i\n", tout);
			}
			pos = strstr(value, "string_escape=");
			if (pos != NULL) {
				pos = &pos[strlen("string_escape=")];
				if (strncmp(pos, "none", strlen("none")) == 0)
					rule_add_token(&rule_tmp, TK_A_STRING_ESCAPE_NONE, 0, NULL, NULL);
				else if (strncmp(pos, "replace", strlen("replace")) == 0)
					rule_add_token(&rule_tmp, TK_A_STRING_ESCAPE_REPLACE, 0, NULL, NULL);
			}
			if (strstr(value, "all_partitions") != NULL) {
				int num = DEFAULT_FAKE_PARTITIONS_COUNT;

				rule_add_token(&rule_tmp, TK_A_NUM_FAKE_PART, 0, NULL, &num);
				dbg(rules->udev, "creation of partition nodes requested\n");
			}
			valid = 1;
			continue;
		}
		err(rules->udev, "unknown key '%s' in %s:%u\n", key, filename, lineno);
	}

	if (physdev)
		err(rules->udev, "PHYSDEV* values are deprecated and not available on recent kernels, \n"
		    "please fix it in %s:%u", filename, lineno);

	/* skip line if not any valid key was found */
	if (!valid)
		goto invalid;

	/* add rule token */
	if (add_token(rules, &rule_tmp.rule) != 0)
		goto invalid;

	/* add tokens to list, sorted by type */
	if (sort_token(rules, &rule_tmp) != 0)
		goto invalid;
	return 0;
invalid:
	err(rules->udev, "invalid rule '%s:%u'\n", filename, lineno);
	return -1;
}

static int parse_file(struct udev_rules *rules, const char *filename)
{
	FILE *f;
	unsigned int filename_off;
	unsigned int first_token;
	char line[UTIL_LINE_SIZE];
	int line_nr = 0;
	unsigned int i;

	info(rules->udev, "reading '%s' as rules file\n", filename);

	f = fopen(filename, "r");
	if (f == NULL)
		return -1;

	filename_off = add_string(rules, filename);
	first_token = rules->token_cur;

	while(fgets(line, sizeof(line), f) != NULL) {
		char *key;
		size_t len;

		/* skip whitespace */
		line_nr++;
		key = line;
		while (isspace(key[0]))
			key++;

		/* comment */
		if (key[0] == '#')
			continue;

		len = strlen(line);
		if (len < 3)
			continue;

		/* continue reading if backslash+newline is found */
		while (line[len-2] == '\\') {
			if (fgets(&line[len-2], (sizeof(line)-len)+2, f) == NULL)
				break;
			line_nr++;
			len = strlen(line);
		}

		if (len+1 >= sizeof(line)) {
			err(rules->udev, "line too long '%s':%u, ignored\n", filename, line_nr);
			continue;
		}
		add_rule(rules, key, filename, filename_off, line_nr);
	}
	fclose(f);

	/* link GOTOs to LABEL rules in this file to be able to fast-forward */
	for (i = first_token+1; i < rules->token_cur; i++) {
		if (rules->tokens[i].type == TK_A_GOTO) {
			char *label = &rules->buf[rules->tokens[i].key.value_off];
			unsigned int j;

			for (j = i+1; j < rules->token_cur; j++) {
				if (rules->tokens[j].type != TK_RULE)
					continue;
				if (rules->tokens[j].rule.label_off == 0)
					continue;
				if (strcmp(label, &rules->buf[rules->tokens[j].rule.label_off]) != 0)
					continue;
				rules->tokens[i].key.rule_goto = j;
			}
			if (rules->tokens[i].key.rule_goto == 0)
				err(rules->udev, "GOTO '%s' has no matching label in: '%s'\n", label, filename);
		}
	}
	return 0;
}

static int add_matching_files(struct udev *udev, struct udev_list_node *file_list, const char *dirname, const char *suffix)
{
	struct dirent *ent;
	DIR *dir;
	char filename[UTIL_PATH_SIZE];

	dbg(udev, "open directory '%s'\n", dirname);
	dir = opendir(dirname);
	if (dir == NULL) {
		err(udev, "unable to open '%s': %m\n", dirname);
		return -1;
	}

	while (1) {
		ent = readdir(dir);
		if (ent == NULL || ent->d_name[0] == '\0')
			break;

		if ((ent->d_name[0] == '.') || (ent->d_name[0] == '#'))
			continue;

		/* look for file matching with specified suffix */
		if (suffix != NULL) {
			const char *ext;

			ext = strrchr(ent->d_name, '.');
			if (ext == NULL)
				continue;
			if (strcmp(ext, suffix) != 0)
				continue;
		}
		dbg(udev, "put file '%s/%s' into list\n", dirname, ent->d_name);

		snprintf(filename, sizeof(filename), "%s/%s", dirname, ent->d_name);
		filename[sizeof(filename)-1] = '\0';
		udev_list_entry_add(udev, file_list, filename, NULL, 1, 1);
	}

	closedir(dir);
	return 0;
}

struct udev_rules *udev_rules_new(struct udev *udev, int resolve_names)
{
	struct udev_rules *rules;
	struct stat statbuf;
	char filename[PATH_MAX];
	struct udev_list_node file_list;
	struct udev_list_entry *file_loop, *file_tmp;
	unsigned int prev_rule;
	struct token end_token;
	unsigned int i;

	rules = malloc(sizeof(struct udev_rules));
	if (rules == NULL)
		return NULL;
	memset(rules, 0x00, sizeof(struct udev_rules));
	rules->udev = udev;
	rules->resolve_names = resolve_names;
	udev_list_init(&file_list);

	/* init token array and string buffer */
	rules->tokens = malloc(PREALLOC_TOKEN * sizeof(struct token));
	if (rules->tokens != NULL)
		rules->token_max = PREALLOC_TOKEN;
	rules->buf = malloc(PREALLOC_STRBUF);
	if (rules->buf != NULL)
		rules->buf_max = PREALLOC_STRBUF;
	info(udev, "prealloc %zu bytes tokens (%u * %zu bytes), %zu bytes buffer\n",
	     rules->token_max * sizeof(struct token), rules->token_max, sizeof(struct token), rules->buf_max);
	/* offset 0 in the string buffer is always empty */
	add_string(rules, "");

	if (udev_get_rules_path(udev) != NULL) {
		/* custom rules location for testing */
		add_matching_files(udev, &file_list, udev_get_rules_path(udev), ".rules");
	} else {
		struct udev_list_node sort_list;
		struct udev_list_entry *sort_loop, *sort_tmp;

		/* read user/custom rules */
		add_matching_files(udev, &file_list, SYSCONFDIR "/udev/rules.d", ".rules");

		/* read dynamic/temporary rules */
		util_strlcpy(filename, udev_get_dev_path(udev), sizeof(filename));
		util_strlcat(filename, "/.udev/rules.d", sizeof(filename));
		if (stat(filename, &statbuf) != 0) {
			util_create_path(udev, filename);
			udev_selinux_setfscreatecon(udev, filename, S_IFDIR|0755);
			mkdir(filename, 0755);
			udev_selinux_resetfscreatecon(udev);
		}
		udev_list_init(&sort_list);
		add_matching_files(udev, &sort_list, filename, ".rules");

		/* read default rules */
		add_matching_files(udev, &sort_list, UDEV_PREFIX "/lib/udev/rules.d", ".rules");

		/* sort all rules files by basename into list of files */
		udev_list_entry_foreach_safe(sort_loop, sort_tmp, udev_list_get_entry(&sort_list)) {
			const char *sort_name = udev_list_entry_get_name(sort_loop);
			const char *sort_base = strrchr(sort_name, '/');

			if (sort_base == NULL)
				continue;

			udev_list_entry_foreach_safe(file_loop, file_tmp, udev_list_get_entry(&file_list)) {
				const char *file_name = udev_list_entry_get_name(file_loop);
				const char *file_base = strrchr(file_name, '/');

				if (file_base == NULL)
					continue;
				if (strcmp(file_base, sort_base) == 0) {
					info(udev, "rule file basename '%s' already added, ignoring '%s'\n",
					     file_name, sort_name);
					udev_list_entry_remove(sort_loop);
					sort_loop = NULL;
					break;
				}
				if (strcmp(file_base, sort_base) > 0)
					break;
			}
			if (sort_loop != NULL)
				udev_list_entry_move_before(sort_loop, file_loop);
		}
	}

	/* parse list of files */
	udev_list_entry_foreach_safe(file_loop, file_tmp, udev_list_get_entry(&file_list)) {
		const char *file_name = udev_list_entry_get_name(file_loop);

		if (stat(file_name, &statbuf) == 0 && statbuf.st_size > 0)
			parse_file(rules, file_name);
		else
			info(udev, "can not read '%s'\n", file_name);
		udev_list_entry_remove(file_loop);
	}

	memset(&end_token, 0x00, sizeof(struct token));
	end_token.type = TK_END;
	add_token(rules, &end_token);

	/* shrink allocate buffers */
	if (rules->token_cur < rules->token_max) {
		struct token *tokens;

		tokens = realloc(rules->tokens, rules->token_cur * sizeof(struct token));
		if (tokens != NULL || rules->token_cur == 0) {
			rules->tokens = tokens;
			rules->token_max = rules->token_cur;
		}
	}
	if (rules->buf_cur < rules->buf_max) {
		char *buf;

		buf = realloc(rules->buf, rules->buf_cur);
		if (buf != NULL || rules->buf_cur == 0) {
			rules->buf = buf;
			rules->buf_max = rules->buf_cur;
		}
	}
	info(udev, "shrunk to %lu bytes tokens (%u * %zu bytes), %zu bytes buffer\n",
	     rules->token_max * sizeof(struct token), rules->token_max, sizeof(struct token), rules->buf_max);

	/* link all TK_RULE tokens to be able to fast-forward to next TK_RULE */
	prev_rule = 0;
	for (i = 1; i < rules->token_cur; i++) {
		if (rules->tokens[i].type == TK_RULE) {
			rules->tokens[prev_rule].rule.next_rule = i;
			prev_rule = i;
		}
	}
	dump_rules(rules);
	return rules;
}

void udev_rules_unref(struct udev_rules *rules)
{
	if (rules == NULL)
		return;
	free(rules->tokens);
	free(rules->buf);
	free(rules);
}

static int match_key(struct udev_rules *rules, struct token *token, const char *val)
{
	const char *key_name = token_str[token->type];
	char *key_value = &rules->buf[token->key.value_off];
	char *pos;
	int match = 0;

	if (val == NULL)
		val = "";

	/* look for a matching string, parts are separated by '|' */
	if (strchr(key_value, '|') != NULL) {
		char value[UTIL_PATH_SIZE];

		util_strlcpy(value, &rules->buf[token->key.value_off], sizeof(value));
		key_value = value;
		while (key_value != NULL) {
			pos = strchr(key_value, '|');
			if (pos != NULL) {
				pos[0] = '\0';
				pos = &pos[1];
			}
			dbg(rules->udev, "match %s '%s' <-> '%s'\n", key_name, key_value, val);
			match = (fnmatch(key_value, val, 0) == 0);
			if (match)
				break;
			key_value = pos;
		}
	} else {
		match = (fnmatch(key_value, val, 0) == 0);
	}

	if (match && (token->key.op == KEY_OP_MATCH)) {
		dbg(rules->udev, "%s is true (matching value)\n", key_name);
		return 0;
	}
	if (!match && (token->key.op == KEY_OP_NOMATCH)) {
		dbg(rules->udev, "%s is true (non-matching value)\n", key_name);
		return 0;
	}
	dbg(rules->udev, "%s is not true\n", key_name);
	return -1;
}

static int match_attr(struct udev_rules *rules, struct udev_device *dev, struct udev_event *event, struct token *cur)
{
	char attr[UTIL_PATH_SIZE];
	const char *key_name = &rules->buf[cur->key.attr_off];
	const char *key_value = &rules->buf[cur->key.value_off];
	char value[UTIL_NAME_SIZE] = "";
	size_t len;

	util_strlcpy(attr, key_name, sizeof(attr));
	util_resolve_subsys_kernel(event->udev, attr, value, sizeof(value), 1);
	if (value[0] == '\0') {
		const char *val;

		val = udev_device_get_sysattr_value(dev, key_name);
		if (val != NULL)
			util_strlcpy(value, val, sizeof(value));
	}
	if (value[0]=='\0')
		return -1;

	/* strip trailing whitespace of value, if not asked to match for it */
	len = strlen(key_value);
	if (len > 0 && !isspace(key_value[len-1])) {
		len = strlen(value);
		while (len > 0 && isspace(value[--len]))
			value[len] = '\0';
		dbg(rules->udev, "removed trailing whitespace from '%s'\n", value);
	}
	return match_key(rules, cur, value);
}

enum escape_type {
	ESCAPE_UNSET,
	ESCAPE_NONE,
	ESCAPE_REPLACE,
};

int udev_rules_apply_to_event(struct udev_rules *rules, struct udev_event *event)
{
	struct token *rule;
	struct token *cur;

	if (rules->tokens == NULL)
		return -1;

	/* loop through token list, match, run actions or forward to next rule */
	cur = &rules->tokens[0];
	while (cur != NULL && cur->type != TK_END) {
		enum escape_type esc = ESCAPE_UNSET;
		unsigned int idx;

		dump_token(rules, cur);
		switch (cur->type) {
		case TK_RULE:
			/* current rule */
			rule = cur;
			esc = ESCAPE_UNSET;
			break;
		case TK_M_WAITFOR:
			{
				char filename[UTIL_PATH_SIZE];
				int found;

				util_strlcpy(filename, &rules->buf[cur->key.value_off], sizeof(filename));
				udev_event_apply_format(event, filename, sizeof(filename));
				found = (wait_for_file(event->dev, filename, 10) == 0);
				if (!found && (cur->key.op != KEY_OP_NOMATCH))
					goto nomatch;
				break;
			}
		case TK_M_ACTION:
			if (match_key(rules, cur, udev_device_get_action(event->dev)) != 0)
				goto nomatch;
			break;
		case TK_M_DEVPATH:
			if (match_key(rules, cur, udev_device_get_devpath(event->dev)) != 0)
				goto nomatch;
			break;
		case TK_M_KERNEL:
			if (match_key(rules, cur, udev_device_get_sysname(event->dev)) != 0)
				goto nomatch;
			break;
		case TK_M_DEVLINK:
			{
				size_t devlen = strlen(udev_get_dev_path(event->udev))+1;
				struct udev_list_entry *list_entry;
				int match = 0;

				udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(event->dev)) {
					const char *devlink;

					devlink =  &udev_list_entry_get_name(list_entry)[devlen];
					if (match_key(rules, cur, devlink) == 0) {
						match = 1;
						break;
					}
				}
				if (!match)
					goto nomatch;
				break;
			}
		case TK_M_NAME:
			if (match_key(rules, cur, event->name) != 0)
				goto nomatch;
			break;
		case TK_M_ENV:
			{
				struct udev_list_entry *list_entry;
				const char *key_name = &rules->buf[cur->key.attr_off];
				const char *value;

				list_entry = udev_device_get_properties_list_entry(event->dev);
				list_entry = udev_list_entry_get_by_name(list_entry, key_name);
				value = udev_list_entry_get_value(list_entry);
				if (value == NULL) {
					dbg(event->udev, "ENV{%s} is not set, treat as empty\n", key_name);
					value = "";
				}
				if (match_key(rules, cur, value))
					goto nomatch;
				break;
			}
		case TK_M_SUBSYSTEM:
			if (match_key(rules, cur, udev_device_get_subsystem(event->dev)) != 0)
				goto nomatch;
			break;
		case TK_M_DRIVER:
			if (match_key(rules, cur, udev_device_get_driver(event->dev)) != 0)
				goto nomatch;
			break;
		case TK_M_ATTR:
			if (match_attr(rules, event->dev, event, cur) != 0)
				goto nomatch;
			break;
		case TK_M_KERNELS:
		case TK_M_SUBSYSTEMS:
		case TK_M_DRIVERS:
		case TK_M_ATTRS:
			{
				struct token *next;

				/* get whole sequence of parent matches */
				next = cur;
				while (next->type < TK_PARENTS_MAX)
					next++;

				/* loop over parents */
				event->dev_parent = event->dev;
				while (1) {
					struct token *key;

					dbg(event->udev, "parent: '%s'\n", udev_device_get_syspath(event->dev_parent));
					/* loop over sequence of parent match keys */
					for (key = cur; key < next; key++ ) {
						dump_token(rules, key);
						switch(key->type) {
						case TK_M_KERNELS:
							if (match_key(rules, key, udev_device_get_sysname(event->dev_parent)) != 0)
								goto try_parent;
							break;
						case TK_M_SUBSYSTEMS:
							if (match_key(rules, key, udev_device_get_subsystem(event->dev_parent)) != 0)
								goto try_parent;
							break;
						case TK_M_DRIVERS:
							if (match_key(rules, key, udev_device_get_driver(event->dev_parent)) != 0)
								goto try_parent;
							break;
						case TK_M_ATTRS:
							if (match_attr(rules, event->dev_parent, event, key) != 0)
								goto try_parent;
							break;
						default:
							goto nomatch;
						}
						dbg(event->udev, "parent key matched\n");
					}
					dbg(event->udev, "all parent keys matched\n");
					/* all keys matched */
					break;

				try_parent:
					event->dev_parent = udev_device_get_parent(event->dev_parent);
					if (event->dev_parent == NULL)
						goto nomatch;
				}
				/* move behind our sequence of parent match keys */
				cur = next;
				continue;
			}
		case TK_M_TEST:
			{
				char filename[UTIL_PATH_SIZE];
				struct stat statbuf;
				int match;

				util_strlcpy(filename, &rules->buf[cur->key.value_off], sizeof(filename));
				udev_event_apply_format(event, filename, sizeof(filename));
				if (util_resolve_subsys_kernel(event->udev, NULL, filename, sizeof(filename), 0) != 0)
					if (filename[0] != '/') {
						char tmp[UTIL_PATH_SIZE];

						util_strlcpy(tmp, udev_device_get_syspath(event->dev), sizeof(tmp));
						util_strlcat(tmp, "/", sizeof(tmp));
						util_strlcat(tmp, filename, sizeof(tmp));
						util_strlcpy(filename, tmp, sizeof(filename));
					}

				attr_subst_subdir(filename, sizeof(filename));

				match = (stat(filename, &statbuf) == 0);
				info(event->udev, "'%s' %s", filename, match ? "exists\n" : "does not exist\n");
				if (match && cur->key.mode > 0) {
					match = ((statbuf.st_mode & cur->key.mode) > 0);
					info(event->udev, "'%s' has mode=%#o and %s %#o\n", filename, statbuf.st_mode,
					     match ? "matches" : "does not match", cur->key.mode);
				}
				if (match && cur->key.op == KEY_OP_NOMATCH)
					goto nomatch;
				if (!match && cur->key.op == KEY_OP_MATCH)
					goto nomatch;
				break;
			}
		case TK_M_PROGRAM:
			{
				char program[UTIL_PATH_SIZE];
				char **envp;
				char result[UTIL_PATH_SIZE];

				util_strlcpy(program, &rules->buf[cur->key.value_off], sizeof(program));
				udev_event_apply_format(event, program, sizeof(program));
				envp = udev_device_get_properties_envp(event->dev);
				if (util_run_program(event->udev, program, envp, result, sizeof(result), NULL) != 0) {
					event->program_result[0] = '\0';
					if (cur->key.op != KEY_OP_NOMATCH)
						goto nomatch;
				} else {
					int count;

					util_remove_trailing_chars(result, '\n');
					if (esc == ESCAPE_UNSET || esc == ESCAPE_REPLACE) {
						count = util_replace_chars(result, ALLOWED_CHARS_INPUT);
						if (count > 0)
							info(event->udev, "%i character(s) replaced\n" , count);
					}
					util_strlcpy(event->program_result, result, sizeof(event->program_result));
					if (cur->key.op == KEY_OP_NOMATCH)
						goto nomatch;
				}
				break;
			}
		case TK_M_IMPORT_FILE:
			{
				char import[UTIL_PATH_SIZE];

				util_strlcpy(import, &rules->buf[cur->key.value_off], sizeof(import));
				udev_event_apply_format(event, import, sizeof(import));
				if (import_file_into_properties(event->dev, import) != 0)
					if (cur->key.op != KEY_OP_NOMATCH)
						goto nomatch;
				break;
			}
		case TK_M_IMPORT_PROG:
			{
				char import[UTIL_PATH_SIZE];

				util_strlcpy(import, &rules->buf[cur->key.value_off], sizeof(import));
				udev_event_apply_format(event, import, sizeof(import));
				if (import_program_into_properties(event->dev, import) != 0)
					if (cur->key.op != KEY_OP_NOMATCH)
						goto nomatch;
				break;
			}
		case TK_M_IMPORT_PARENT:
			{
				char import[UTIL_PATH_SIZE];

				util_strlcpy(import, &rules->buf[cur->key.value_off], sizeof(import));
				udev_event_apply_format(event, import, sizeof(import));
				if (import_parent_into_properties(event->dev, import) != 0)
					if (cur->key.op != KEY_OP_NOMATCH)
						goto nomatch;
				break;
			}
		case TK_M_RESULT:
			if (match_key(rules, cur, event->program_result) != 0)
				goto nomatch;
			break;

		case TK_A_IGNORE_DEVICE:
			event->ignore_device = 1;
			return 0;
			break;
		case TK_A_STRING_ESCAPE_NONE:
			esc = ESCAPE_NONE;
			break;
		case TK_A_STRING_ESCAPE_REPLACE:
			esc = ESCAPE_REPLACE;
			break;
		case TK_A_NUM_FAKE_PART:
			if (strcmp(udev_device_get_subsystem(event->dev), "block") != 0)
				break;
			if (udev_device_get_sysnum(event->dev) != NULL)
				break;
			udev_device_set_num_fake_partitions(event->dev, cur->key.num_fake_part);
			break;
		case TK_A_DEVLINK_PRIO:
			udev_device_set_devlink_priority(event->dev, cur->key.devlink_prio);
			break;
		case TK_A_OWNER:
			{
				char owner[UTIL_NAME_SIZE];

				if (event->owner_final)
					break;
				if (cur->key.op == KEY_OP_ASSIGN_FINAL)
					event->owner_final = 1;
				util_strlcpy(owner,  &rules->buf[cur->key.value_off], sizeof(owner));
				udev_event_apply_format(event, owner, sizeof(owner));
				event->uid = util_lookup_user(event->udev, owner);
				break;
			}
		case TK_A_GROUP:
			{
				char group[UTIL_NAME_SIZE];

				if (event->group_final)
					break;
				if (cur->key.op == KEY_OP_ASSIGN_FINAL)
					event->group_final = 1;
				util_strlcpy(group,  &rules->buf[cur->key.value_off], sizeof(group));
				udev_event_apply_format(event, group, sizeof(group));
				event->gid = util_lookup_group(event->udev, group);
				break;
			}
		case TK_A_MODE:
			{
				char mode[UTIL_NAME_SIZE];
				char *endptr;

				if (event->mode_final)
					break;
				if (cur->key.op == KEY_OP_ASSIGN_FINAL)
					event->mode_final = 1;
				util_strlcpy(mode,  &rules->buf[cur->key.value_off], sizeof(mode));
				udev_event_apply_format(event, mode, sizeof(mode));
				event->mode = strtol(mode, &endptr, 8);
				if (endptr[0] != '\0') {
					err(event->udev, "invalide mode '%s' set default mode 0660\n", mode);
					event->mode = 0660;
				}
				break;
			}
		case TK_A_OWNER_ID:
			if (event->owner_final)
				break;
			if (cur->key.op == KEY_OP_ASSIGN_FINAL)
				event->owner_final = 1;
			event->uid = cur->key.uid;
			break;
		case TK_A_GROUP_ID:
			if (event->group_final)
				break;
			if (cur->key.op == KEY_OP_ASSIGN_FINAL)
				event->group_final = 1;
			event->gid = cur->key.gid;
			break;
		case TK_A_MODE_ID:
			if (event->mode_final)
				break;
			if (cur->key.op == KEY_OP_ASSIGN_FINAL)
				event->mode_final = 1;
			event->mode = cur->key.mode;
			break;
		case TK_A_ENV:
			{
				const char *name = &rules->buf[cur->key.attr_off];
				char *value = &rules->buf[cur->key.value_off];

				if (value[0] != '\0') {
					char temp_value[UTIL_NAME_SIZE];
					struct udev_list_entry *entry;

					util_strlcpy(temp_value, value, sizeof(temp_value));
					udev_event_apply_format(event, temp_value, sizeof(temp_value));
					entry = udev_device_add_property(event->dev, name, temp_value);
					/* store in db */
					udev_list_entry_set_flag(entry, 1);
				} else {
					udev_device_add_property(event->dev, name, NULL);
				}
				break;
			}
		case TK_A_NAME:
			{
				const char *name  = &rules->buf[cur->key.value_off];
				int count;

				if (event->name_final)
					break;
				if (cur->key.op == KEY_OP_ASSIGN_FINAL)
					event->name_final = 1;
				if (name[0] == '\0') {
					event->name[0] = '\0';
					event->name_ignore = 1;
					break;
				}
				event->name_ignore = 0;
				util_strlcpy(event->name, name, sizeof(event->name));
				udev_event_apply_format(event, event->name, sizeof(event->name));
				if (esc == ESCAPE_UNSET || esc == ESCAPE_REPLACE) {
					count = util_replace_chars(event->name, ALLOWED_CHARS_FILE);
					if (count > 0)
						info(event->udev, "%i character(s) replaced\n", count);
				}
				break;
			}
		case TK_A_DEVLINK:
			{
				char temp[UTIL_PATH_SIZE];
				char filename[UTIL_PATH_SIZE];
				char *pos, *next;
				int count = 0;

				if (event->devlink_final)
					break;
				if (cur->key.op == KEY_OP_ASSIGN_FINAL)
					event->devlink_final = 1;
				if (cur->key.op == KEY_OP_ASSIGN || cur->key.op == KEY_OP_ASSIGN_FINAL)
					udev_device_cleanup_devlinks_list(event->dev);

				/* allow  multiple symlinks separated by spaces */
				util_strlcpy(temp, &rules->buf[cur->key.value_off], sizeof(temp));
				udev_event_apply_format(event, temp, sizeof(temp));
				if (esc == ESCAPE_UNSET)
					count = util_replace_chars(temp, ALLOWED_CHARS_FILE " ");
				else if (esc == ESCAPE_REPLACE)
					count = util_replace_chars(temp, ALLOWED_CHARS_FILE);
				if (count > 0)
					info(event->udev, "%i character(s) replaced\n" , count);
				dbg(event->udev, "rule applied, added symlink(s) '%s'\n", temp);
				pos = temp;
				while (isspace(pos[0]))
					pos++;
				next = strchr(pos, ' ');
				while (next) {
					next[0] = '\0';
					info(event->udev, "add symlink '%s'\n", pos);
					util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, pos, sizeof(filename));
					udev_device_add_devlink(event->dev, filename);
					while (isspace(next[1]))
						next++;
					pos = &next[1];
					next = strchr(pos, ' ');
				}
				if (pos[0] != '\0') {
					info(event->udev, "add symlink '%s'\n", pos);
					util_strlcpy(filename, udev_get_dev_path(event->udev), sizeof(filename));
					util_strlcat(filename, "/", sizeof(filename));
					util_strlcat(filename, pos, sizeof(filename));
					udev_device_add_devlink(event->dev, filename);
				}
			}
			break;
		case TK_A_EVENT_TIMEOUT:
			udev_device_set_event_timeout(event->dev, cur->key.event_timeout);
			break;
		case TK_A_IGNORE_REMOVE:
			udev_device_set_ignore_remove(event->dev, 1);
			break;
		case TK_A_ATTR:
			{
				const char *key_name = &rules->buf[cur->key.attr_off];
				char attr[UTIL_PATH_SIZE];
				char value[UTIL_NAME_SIZE];
				FILE *f;

				util_strlcpy(attr, key_name, sizeof(attr));
				if (util_resolve_subsys_kernel(event->udev, key_name, attr, sizeof(attr), 0) != 0) {
					util_strlcpy(attr, udev_device_get_syspath(event->dev), sizeof(attr));
					util_strlcat(attr, "/", sizeof(attr));
					util_strlcat(attr, key_name, sizeof(attr));
				}

				attr_subst_subdir(attr, sizeof(attr));

				util_strlcpy(value, &rules->buf[cur->key.value_off], sizeof(value));
				udev_event_apply_format(event, value, sizeof(value));
				info(event->udev, "writing '%s' to sysfs file '%s'\n", value, attr);
				f = fopen(attr, "w");
				if (f != NULL) {
					if (!event->test)
						if (fprintf(f, "%s", value) <= 0)
							err(event->udev, "error writing ATTR{%s}: %m\n", attr);
					fclose(f);
				} else {
					err(event->udev, "error opening ATTR{%s} for writing: %m\n", attr);
				}
				break;
			}
		case TK_A_RUN:
			{
				struct udev_list_entry *list_entry;

				if (cur->key.op == KEY_OP_ASSIGN || cur->key.op == KEY_OP_ASSIGN_FINAL)
					udev_list_cleanup_entries(event->udev, &event->run_list);
				list_entry = udev_list_entry_add(event->udev, &event->run_list,
								 &rules->buf[cur->key.value_off], NULL, 1, 0);
				if (cur->key.ignore_error)
					udev_list_entry_set_flag(list_entry, 1);
				break;
			}
		case TK_A_GOTO:
			cur = &rules->tokens[cur->key.rule_goto];
			continue;
		case TK_A_LAST_RULE:
			break;

		case TK_PARENTS_MAX:
		case TK_END:
		case TK_UNDEF:
			err(rules->udev, "wrong type %u\n", cur->type);
			goto nomatch;
		}

		cur++;
		continue;
	nomatch:
		/* fast-forward to next rule */
		idx = rule->rule.next_rule;
		if (idx == 0)
			break;
		dbg(rules->udev, "forward to rule: %u\n", idx);
		cur = &rules->tokens[idx];
	}
	return 0;
}
