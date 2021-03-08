#ifndef VS_CWAF_SIGN_CHECK_H
#define VS_CWAF_SIGN_CHECK_H

typedef struct sign_vars{    
    union {
		int i;
		char *p;
    }un;
    int len;
    unsigned int id; 
}proto_data;

#define SIGN_CONF_SET_CONF_PATH			1
#define SIGN_CONF_SET_ERRLOG_PATH		2
#define SIGN_CONF_SET_LOG_THRESHOLD		3
#define SIGN_CONF_SET_BLOCK_THRESHOLD	4
#define SIGN_CONF_SET_BLOCK_TYPE		5

//log threshold enum define, relate to NGX_SIGN_LOG_XXX enum
#define SIGN_CONF_LOG_NONE	0
#define SIGN_CONF_LOG_BLOCK	1
#define SIGN_CONF_LOG_ALL	2

//block threshold enum define, relate to NGX_SIGN_BLOCK_XXX enum
#define SIGN_CONF_BLOCK_NONE	0
#define SIGN_CONF_BLOCK_HIGH	1
#define SIGN_CONF_BLOCK_MEDIUM	2
#define SIGN_CONF_BLOCK_ALL		3

//block type enum define
#define SIGN_CONF_BLOCK_TYPE_FORWARD	0	//forward to upstream server
#define SIGN_CONF_BLOCK_TYPE_REDIRECT	1	//rediret to a new url
#define SIGN_CONF_BLOCK_TYPE_ERRCODE	2	//return errcode

/*
 *	@desc:
 *	@input: file_list(char *file_list[]); num: number of file in the list
 *	@output:
 *	@return: 0 if no error, otherwise errcode returns
 *	@tips:
 **/
int sign_check_init(void *file_list,int num); 

/*
 *	@desc:
 *	@input: ngx_data: proto_data array; len: number of proto_data array
 *	@output: if_block, 1 if block needed, 0 if block not needed
 *	@return: >0, match num; =0, no match; <0 internal error
 *	@tips:
 **/
int sign_check_check(void * ngx_data,int len, int *if_block); 

/*
 *	@desc:
 *	@input:
 *	@output: 
 *	@return: 0 if no error occurs, otherwise, error
 *	@tips:
 **/
int sign_check_send_log(unsigned char *request_headers, unsigned int len);

/*
 *	@desc:
 *	@input: item: enum num of specific item to be configured; val: val to item
 *	@output: 
 *	@return: 0 if no error occurs, otherwise
 *	@tips:
 **/
int sign_check_set_conf(int item, void *val);

void sign_check_clean(void);


#include "vs_proto_var_id.h"

#endif
