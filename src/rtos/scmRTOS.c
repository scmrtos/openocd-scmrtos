



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/time_support.h>
#include <jtag/jtag.h>
#include "target/target.h"
#include "target/target_type.h"
#include "rtos.h"
#include "helper/log.h"
#include "helper/types.h"
#include "rtos_standard_stackings.h"

          
static int scmRTOS_detect_rtos               (struct target *target);
static int scmRTOS_create                    (struct target *target);
static int scmRTOS_update_threads            (struct rtos *rtos);
static int scmRTOS_get_thread_reg_list       (struct rtos *rtos, int64_t thread_id, char **hex_reg_list);
static int scmRTOS_get_symbol_list_to_lookup (symbol_table_elem_t *symbol_list[]);

struct rtos_type scmRTOS_rtos = 
{
    .name                      = "scmRTOS",
    .detect_rtos               = scmRTOS_detect_rtos,
    .create                    = scmRTOS_create,
    .update_threads            = scmRTOS_update_threads,
    .get_thread_reg_list       = scmRTOS_get_thread_reg_list,
    .get_symbol_list_to_lookup = scmRTOS_get_symbol_list_to_lookup
};

enum 
{
    SYMBOL_ID_KERNEL        = 0,
    SYMBOL_ID_PROCESS_TABLE = 1
};

static const char * const scmRTOS_symbol_list[] = 
{
    "OS::Kernel",
    "OS::TKernel::ProcessTable",
    NULL 
};

struct scmRTOS_params 
{
    
};

