/***************************************************************************
 *   Copyright (C) 2011 by Broadcom Corporation                            *
 *   Evan Hunter - ehunter@broadcom.com                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/
//
//   Copyright (c) 2016, scmRTOS Team
//

//------------------------------------------------------------------------------
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
#include "rtos_scmRTOS_stackings.h"
          
//------------------------------------------------------------------------------
static bool scmRTOS_detect_rtos               (struct target *target);
static int scmRTOS_create                    (struct target *target);
static int scmRTOS_update_proc_info          (struct rtos *rtos);
static int scmRTOS_get_proc_reg_list         (struct rtos *rtos, int64_t thread_id, struct rtos_reg **reg_list, int *num_regs);
static int scmRTOS_get_symbol_list_to_lookup (struct symbol_table_elem *symbol_list[]);
static int scmRTOS_clean                     (struct target *target);
//------------------------------------------------------------------------------
//
//    General
//
#define LOG_DBG LOG_OUTPUT // LOG_DEBUG

//--------------------------------------------------------------------
//
//    Literals
//
enum
{
    TARGET_POINTER_SIZE = 4,
    MAX_PROCESS_COUNT   = 31,
    PROCESS_NAME_LEN    = 64
};

enum    // 'cm' prefix means 'cortex-m'
{
    //  OS::TKernel members
    cmCUR_PROC_PRIORITY_OFFSET = 0,
    cmCUR_PROC_PRIORITY_SIZE   = 4,
    cmREADY_PROCESS_MAP_OFFSET = cmCUR_PROC_PRIORITY_OFFSET + cmCUR_PROC_PRIORITY_SIZE,
    cmREADY_PROCESS_MAP_SIZE   = 4,
    cmISR_NEST_COUNT_OFFSET    = cmREADY_PROCESS_MAP_OFFSET + cmREADY_PROCESS_MAP_SIZE,
    cmISR_NEST_COUNT_SIZE      = 4,
    cmPROC_COUNT_OFFSET        = cmISR_NEST_COUNT_OFFSET + cmISR_NEST_COUNT_SIZE,
    cmPROC_COUNT_SIZE          = 4,

    //  OS::TBaseProcess members
    cmSTACK_POINTER_OFFSET     = 0,
    cmSTACK_POINTER_SIZE       = 4,
    cmTIMEOUT_OFFSET           = cmSTACK_POINTER_OFFSET + cmSTACK_POINTER_SIZE
};
//------------------------------------------------------------------------------
//
//    Types
//
//------------------------------------------------------------------------------
enum 
{
    SID_DEBUG_INFO    = 0,
    SID_KERNEL        = 1,
    SID_PROCESS_TABLE = 2,
    SID_IDLE_PROC     = 3
};

typedef struct
{
    const char *name;
    bool        optional;
} 
symbols_t;
//------------------------------------------------------------------------------
typedef struct  
{
    // general
    const char          *target_name;
    const unsigned char  pointer_size;
    uint32_t             ProcessTable[MAX_PROCESS_COUNT];
    
    // kernel class members
    const unsigned char  CurProcPriority_offset;
    const unsigned char  CurProcPriority_size;
    const unsigned char  ReadyProcessMap_offset;
    const unsigned char  ReadyProcessMap_size;
    const unsigned char  PROC_COUNT_offset;
    const unsigned char  PROC_COUNT_size;
    
    // process class members
    const unsigned char  StackPointer_offset;
    const unsigned char  StackPointer_size;
    const unsigned char  Timeout_offset;
    
    // openocd
    const struct         rtos_register_stacking *stacking_info;
    
}
scmRTOS_params_t;
//------------------------------------------------------------------------------
typedef struct 
{
    uint8_t PROCESS_COUNT;
    uint8_t TIMEOUT_SIZE;
    uint8_t NAME_OFFSET;
}
os_debug_info_t;
//------------------------------------------------------------------------------
typedef struct
{
    const uint32_t  DebugInfoAddr;
    const uint32_t  KernelAddr;
    const uint32_t  ProcessTableAddr;
    const uint32_t  IdleProcAddr;
    bool            ReversePrioOrder;
    os_debug_info_t DebugInfo;
    uint32_t        MaxProcNameLen;
}
os_info_t;
//------------------------------------------------------------------------------
typedef struct 
{
    uint32_t CurProcPriority;
    uint32_t ReadyProcessMap;
}
os_kernel_t;
//------------------------------------------------------------------------------
typedef struct 
{
    uint32_t StackPointer;
    uint32_t Timeout;
    uint32_t Priority;
    bool     Ready;
    char     Name[PROCESS_NAME_LEN];
}
os_process_t;
//------------------------------------------------------------------------------
static int get_kernel_data   (struct rtos *rtos, os_info_t *os_info, os_kernel_t *os_kernel);
static int get_processes_data(struct rtos *rtos, os_info_t *os_info, os_kernel_t *os_kernel, os_process_t *os_processes);
static int renew_proc_info   (struct rtos *rtos, os_info_t *os_info, os_kernel_t *os_kernel, os_process_t *os_processes);
//------------------------------------------------------------------------------
//
//    Objects
//
//------------------------------------------------------------------------------
const struct rtos_type scmRTOS_rtos = 
{
    .name                      = "scmRTOS",
    .detect_rtos               = scmRTOS_detect_rtos,
    .create                    = scmRTOS_create,
    .update_threads            = scmRTOS_update_proc_info,
    .get_thread_reg_list       = scmRTOS_get_proc_reg_list,
    .get_symbol_list_to_lookup = scmRTOS_get_symbol_list_to_lookup,
    .clean                     = scmRTOS_clean,
};
//------------------------------------------------------------------------------
static const symbols_t scmRTOS_symbols[] = 
{
    { "OS::DebugInfo",             false },
    { "OS::Kernel",                false },
    { "OS::TKernel::ProcessTable", false },
    { "OS::IdleProc",              false },
    { NULL,                        false }
};
//------------------------------------------------------------------------------
static scmRTOS_params_t scmRTOS_params[] = 
{
    {
        "cortex_m",                   // jlink                       
        TARGET_POINTER_SIZE,
        { 0 },
        cmCUR_PROC_PRIORITY_OFFSET,
        cmCUR_PROC_PRIORITY_SIZE,
        cmREADY_PROCESS_MAP_OFFSET,
        cmREADY_PROCESS_MAP_SIZE,
        cmPROC_COUNT_OFFSET,
        cmPROC_COUNT_SIZE,
        cmSTACK_POINTER_OFFSET,
        cmSTACK_POINTER_SIZE,
        cmTIMEOUT_OFFSET,
        &rtos_standard_cortex_m3_stacking 
    },
    {
        "hla_target",                 // st-link      
        TARGET_POINTER_SIZE,
        { 0 },
        cmCUR_PROC_PRIORITY_OFFSET,
        cmCUR_PROC_PRIORITY_SIZE,
        cmREADY_PROCESS_MAP_OFFSET,
        cmREADY_PROCESS_MAP_SIZE,
        cmPROC_COUNT_OFFSET,
        cmPROC_COUNT_SIZE,
        cmSTACK_POINTER_OFFSET,
        cmSTACK_POINTER_SIZE,
        cmTIMEOUT_OFFSET,
        &rtos_standard_cortex_m3_stacking 
    },
    {
        "arm7tdmi",                 
        TARGET_POINTER_SIZE,
        { 0 },
        cmCUR_PROC_PRIORITY_OFFSET,
        cmCUR_PROC_PRIORITY_SIZE,
        cmREADY_PROCESS_MAP_OFFSET,
        cmREADY_PROCESS_MAP_SIZE,
        cmPROC_COUNT_OFFSET,
        cmPROC_COUNT_SIZE,
        cmSTACK_POINTER_OFFSET,
        cmSTACK_POINTER_SIZE,
        cmTIMEOUT_OFFSET,
        &rtos_scmRTOS_arm7tdmi_stacking 
    }
};
//------------------------------------------------------------------------------
static const int TARGET_COUNT = sizeof(scmRTOS_params)/sizeof(scmRTOS_params[0]);
static const int SYMBOL_COUNT = sizeof(scmRTOS_symbols)/sizeof(scmRTOS_symbols[0]);
//------------------------------------------------------------------------------
//
//    Interface
//
//------------------------------------------------------------------------------
bool scmRTOS_detect_rtos(struct target *target)
{
    if( target->rtos->symbols != NULL ) 
    {
        if( target->rtos->symbols[SID_DEBUG_INFO].address    != 0 &&
            target->rtos->symbols[SID_KERNEL].address        != 0 &&
            target->rtos->symbols[SID_PROCESS_TABLE].address != 0 )
            return true;  // looks like scmRTOS
    }
    return false;
}
//------------------------------------------------------------------------------
int scmRTOS_create(struct target *target)
{
    int i = 0;
    
    while( (i < TARGET_COUNT) && strcmp(scmRTOS_params[i].target_name, target->type->name) )
        ++i;

    if(i >= TARGET_COUNT)
    {
        LOG_ERROR("scmRTOS> E: current target %s does not supported\r\n", target->type->name);
        return -1;
    }

    target->rtos->rtos_specific_params = (void *) &scmRTOS_params[i];
    return 0;
}
//------------------------------------------------------------------------------
int scmRTOS_update_proc_info(struct rtos *rtos)
{
    LOG_DBG("scmRTOS> scmRTOS_update_proc_info \r\n");
    //----------------------------------------------------------------
    //
    //    Setup local RTOS parameters object
    //
    if (rtos->rtos_specific_params == NULL)
        return -1;

    //----------------------------------------------------------------
    //
    //    Check RTOS symbols
    //
    if (rtos->symbols == NULL) {
        LOG_ERROR("scmRTOS> E: no symbols specified");
        return -3;
    }

    if (rtos->symbols[SID_KERNEL].address == 0) {
        LOG_ERROR("scmRTOS> E: OS::Kernel address does not known");
        return -2;
    }
    if (rtos->symbols[SID_PROCESS_TABLE].address == 0) {
        LOG_ERROR("scmRTOS> E: OS::TKernel::ProcessTable address does not known");
        return -2;
    }
    if (rtos->symbols[SID_IDLE_PROC].address == 0) {
        LOG_ERROR("scmRTOS> E: OS::IdleProc address does not known");
        return -2;
    }

    rtos_free_threadlist(rtos);   // delete previous process details if any

    os_info_t os_info = 
    {
        rtos->symbols[SID_DEBUG_INFO].address,
        rtos->symbols[SID_KERNEL].address,
        rtos->symbols[SID_PROCESS_TABLE].address,
        rtos->symbols[SID_IDLE_PROC].address,
        false,                                      // reverse prority order
        { 0 },
        0
    };
    
    
//  for(int i = 0; i < SYMBOL_COUNT - 1; ++i) // last symbol is null
//  {
//      LOG_OUTPUT("----->>> name: %s, value: 0x%lx\r\n", rtos->symbols[i].symbol_name, rtos->symbols[i].address);
//  }
    
    //----------------------------------------------------------------
    //
    //    Get OS::Kernel data
    //
    os_kernel_t os_kernel;
    int res = get_kernel_data(rtos, &os_info, &os_kernel);
    
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not get kernel data");
        return res;
    }
    if(os_kernel.CurProcPriority > MAX_PROCESS_COUNT)
    {
        LOG_DBG("scmRTOS> I: RTOS does not run yet\r\n");
        return ERROR_WAIT;
    }

    //----------------------------------------------------------------
    //
    //    Get RTOS processes data
    //
    os_process_t os_processes[MAX_PROCESS_COUNT];
    res = get_processes_data(rtos, &os_info, &os_kernel, os_processes);
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not get processes data");
        return res;
    }

    res = renew_proc_info(rtos, &os_info, &os_kernel, os_processes);
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not renew processes info");
        return res;
    }
    
    rtos->thread_count = os_info.DebugInfo.PROCESS_COUNT;
    LOG_OUTPUT("***************************************\r\n");
    LOG_OUTPUT("scmRTOS> %u processes, CurProcPriority: %d\n", os_info.DebugInfo.PROCESS_COUNT, os_kernel.CurProcPriority);

    return ERROR_OK;
}
//------------------------------------------------------------------------------
int scmRTOS_get_proc_reg_list(struct rtos *rtos, int64_t thread_id, struct rtos_reg **hex_reg_list, int *num_regs)
{
    int      res;
    uint32_t stack_ptr = 0;

    *hex_reg_list = NULL;
    if (rtos == NULL)
        return -1;

    if (thread_id == 0 || thread_id > MAX_PROCESS_COUNT+1)
        return -2;

    if (rtos->rtos_specific_params == NULL)
        return -1;

    const scmRTOS_params_t *params = (const scmRTOS_params_t *)rtos->rtos_specific_params;
    

    uint32_t sp_addr = params->ProcessTable[thread_id-1] + params->StackPointer_offset;

    // Read the stack pointer value
    res = target_read_buffer(rtos->target, 
                             sp_addr,
                             params->pointer_size,
                             (uint8_t *)&stack_ptr);
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not read stack pointer value");
        return res;
    }
    LOG_DBG("scmRTOS> I: process stack pointer at 0x%x, value 0x%x\r\n", sp_addr, stack_ptr);

    return rtos_generic_stack_read(rtos->target, params->stacking_info, stack_ptr, hex_reg_list, num_regs);
    
}
//------------------------------------------------------------------------------
int scmRTOS_get_symbol_list_to_lookup(struct symbol_table_elem *symbol_list[])
{
     *symbol_list = calloc( SYMBOL_COUNT, sizeof(struct symbol_table_elem) );
    if(!*symbol_list)
    {
        LOG_ERROR("scmRTOS> E: could not allocate memory for symbol list");
        return -1;
    }

    for(int i = 0; i < SYMBOL_COUNT; ++i) 
    {
        (*symbol_list)[i].symbol_name = scmRTOS_symbols[i].name;
        (*symbol_list)[i].address     = 0;
        (*symbol_list)[i].optional    = scmRTOS_symbols[i].optional;
    }

    return 0;
}
//------------------------------------------------------------------------------
static int scmRTOS_clean(struct target *target)
{
    struct rtos * rtos = target->rtos;
    if(rtos == NULL) 
        return ERROR_OK;
        
    scmRTOS_params_t *params = (scmRTOS_params_t *)
        rtos->rtos_specific_params;
    if(params == NULL)
        return ERROR_OK;

    rtos->thread_count = 0;
    
    for(int i = 0; i < MAX_PROCESS_COUNT; ++i) 
        params->ProcessTable[i] = 0;
        
    return ERROR_OK;
}

//------------------------------------------------------------------------------
//
//    Internal Functions
//
//------------------------------------------------------------------------------
int get_kernel_data(struct rtos *rtos, 
                    os_info_t   *os_info, 
                    os_kernel_t *os_kernel)
{
    uint32_t addr;
    uint32_t size;
    int      res;
    
    const scmRTOS_params_t *params = (const scmRTOS_params_t *)rtos->rtos_specific_params;
    
    //  CurProcCount
    addr = os_info->KernelAddr + params->CurProcPriority_offset;
    size = params->CurProcPriority_size;
    res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&os_kernel->CurProcPriority);
    if(res != ERROR_OK)
        return res;
    LOG_DBG("scmRTOS> I: CurProcPriority at 0x%x = %d\r\n", addr, os_kernel->CurProcPriority);

    //  ReadyProcessMap
    addr = os_info->KernelAddr + params->ReadyProcessMap_offset;
    size = params->ReadyProcessMap_size;
    res = target_read_buffer(rtos->target, addr, size, (uint8_t *)&os_kernel->ReadyProcessMap);
    if(res != ERROR_OK)
        return res;
    LOG_DBG("scmRTOS> I: ReadyProcessMap at 0x%x = %d\r\n", addr, os_kernel->ReadyProcessMap);

    //  Debug Data 
    addr = os_info->DebugInfoAddr;
    size = sizeof(os_debug_info_t);
    res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&os_info->DebugInfo);
    if(res != ERROR_OK)
        return res;
    
    const unsigned PROCESS_COUNT = os_info->DebugInfo.PROCESS_COUNT;
    LOG_DBG("scmRTOS> I: PROCESS_COUNT at 0x%x = %d\r\n", addr, PROCESS_COUNT);
    LOG_DBG("scmRTOS> I: TIMEOUT_SIZE = %d\r\n", os_info->DebugInfo.TIMEOUT_SIZE);
    LOG_DBG("scmRTOS> I: NAME_OFFSET = %d\r\n", os_info->DebugInfo.NAME_OFFSET);
    
    if(PROCESS_COUNT > MAX_PROCESS_COUNT           || 
       os_kernel->CurProcPriority > PROCESS_COUNT  ||
       os_kernel->ReadyProcessMap == 0             ||
       os_info->DebugInfo.TIMEOUT_SIZE > 8          // othervise data corruption and segmentation fault can happen
       )   // os not run yet
    {
        LOG_DBG("scmRTOS> I: RTOS does not run yet\r\n");
        return ERROR_WAIT;
    }

    //  ProcessTable
    addr = os_info->ProcessTableAddr;
    size = (PROCESS_COUNT)*(params->pointer_size);
    res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&params->ProcessTable);
    if(res != ERROR_OK)
        return res;
    

    for(unsigned i = 0; i < PROCESS_COUNT; ++i)
    {
        LOG_DBG("scmRTOS> I: ProcessTable[%d]: 0x%x\r\n", i, params->ProcessTable[i]);
    }
    
    //  Check Reverse Priority Order
    const unsigned TIMEOUT_SIZE = os_info->DebugInfo.TIMEOUT_SIZE;
    addr = os_info->IdleProcAddr + params->Timeout_offset + TIMEOUT_SIZE;
    size = 1; // read only lowest byte in word
    uint32_t IdleProcPriority = 0;
    res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&IdleProcPriority);
    if(res != ERROR_OK)
        return res;
    
    if(IdleProcPriority == 0)
    {
        os_info->ReversePrioOrder = true;
    }
    LOG_DBG("scmRTOS> I: Reverse Process Priority is %s\r\n", os_info->ReversePrioOrder ? "true" : "false");
    
    return ERROR_OK;

}
//------------------------------------------------------------------------------
int get_processes_data(struct rtos  *rtos, 
                       os_info_t    *os_info,
                       os_kernel_t  *os_kernel, 
                       os_process_t *os_processes)
{
    const scmRTOS_params_t *params = (const scmRTOS_params_t *)rtos->rtos_specific_params;
    const unsigned PROCESS_COUNT   = os_info->DebugInfo.PROCESS_COUNT;
    
    for(unsigned i = 0; i < PROCESS_COUNT; ++i)
    {
        uint32_t addr;
        uint32_t size;
        uint32_t value;
        int      res;
        
        if(i == 0)
        {
            os_info->MaxProcNameLen = 0;
        }

        uint32_t ProcAddr = params->ProcessTable[i];
        
        const unsigned TIMEOUT_SIZE  = os_info->DebugInfo.TIMEOUT_SIZE;        
        const unsigned PRIORITY_SIZE = 1;  // read only lowest byte      
        
        //  Stack Pointer
        addr = ProcAddr + params->StackPointer_offset;
        size = params->StackPointer_size;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        os_processes[i].StackPointer = value;

        // Timeout
        addr  = ProcAddr + params->Timeout_offset;
        size  = TIMEOUT_SIZE;
        value = 0;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        os_processes[i].Timeout = value;

        // Priority
        addr  = ProcAddr + params->Timeout_offset + TIMEOUT_SIZE;
        size  = PRIORITY_SIZE;
        value = 0;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        os_processes[i].Priority = value;

        // Name
        addr  = ProcAddr + os_info->DebugInfo.NAME_OFFSET;
        size  = params->pointer_size;
        value = 0;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        
        if(value != 0)  // process name exist
        {
            addr = value;
            size = PROCESS_NAME_LEN;
            res  = target_read_buffer(rtos->target, addr, size, (uint8_t*)os_processes[i].Name);
            os_processes[i].Name[PROCESS_NAME_LEN-1] = '\0';
            if(res != ERROR_OK)
                return res;
        }
        else
            strcpy(os_processes[i].Name, "-----");

        uint32_t len = strlen(os_processes[i].Name);
        if(len > os_info->MaxProcNameLen)
        {
            os_info->MaxProcNameLen = len;
        }

        if(os_processes[i].Priority > os_info->DebugInfo.PROCESS_COUNT)
        {
            LOG_ERROR("scmRTOS> E: invalid process priority value: %d", os_processes[i].Priority);
            return ERROR_WAIT;
        }

        LOG_DBG("scmRTOS> I: proc addr: 0x%x > SP: 0x%x, Timeout: %d, Prio: %d, Name: %s\r\n", 
                  ProcAddr, 
                  os_processes[i].StackPointer, 
                  os_processes[i].Timeout,
                  os_processes[i].Priority,
                  os_processes[i].Name);
    }
    return ERROR_OK;
}
//------------------------------------------------------------------------------
int renew_proc_info(struct rtos  *rtos,
                    os_info_t    *os_info,
                    os_kernel_t  *os_kernel, 
                    os_process_t *os_processes)
{
    scmRTOS_params_t *params = (scmRTOS_params_t *)rtos->rtos_specific_params;

    const unsigned PROCESS_COUNT = os_info->DebugInfo.PROCESS_COUNT;
    rtos->thread_details = malloc( sizeof(struct thread_detail)*PROCESS_COUNT );
    
    if (!rtos->thread_details) 
    {
        LOG_ERROR("scmRTOS> E: allocating memory for %d processes", PROCESS_COUNT);
        return ERROR_FAIL;
    }
    
    size_t Proc_name_max_len = 0;    
    for(unsigned i = 0; i < PROCESS_COUNT; ++i)
    {
        size_t Cur_proc_name_len = strlen(os_processes[i].Name);
        if(Cur_proc_name_len > Proc_name_max_len)
            Proc_name_max_len = Cur_proc_name_len;
    }
    
    if(Proc_name_max_len > PROCESS_NAME_LEN - 1)
        Proc_name_max_len = PROCESS_NAME_LEN - 1;
        
    for(unsigned i = 0; i < PROCESS_COUNT; ++i)
    {
        uint32_t ProcAddr = params->ProcessTable[i];
        
        // Ready-to-run
        uint32_t PrioMask = 0x00000001;
        if(os_info->ReversePrioOrder)
        {
            PrioMask <<= os_processes[i].Priority;
        }
        else
        {
            PrioMask <<= PROCESS_COUNT-1;
            PrioMask >>= ( PROCESS_COUNT-1 - os_processes[i].Priority);
        }

        os_processes[i].Ready = os_kernel->ReadyProcessMap & PrioMask;

        char const *info_str = "Suspended";

        if( os_kernel->CurProcPriority == os_processes[i].Priority )
        {
            rtos->current_thread = os_processes[i].Priority + 1;
            info_str = "Active";
        }
        else if(os_processes[i].Ready)
            info_str = "Preempted";

        params->ProcessTable[os_processes[i].Priority] = ProcAddr;
        
        rtos->thread_details[i].threadid        = os_processes[i].Priority + 1;
        rtos->thread_details[i].exists          = true;
        rtos->thread_details[i].thread_name_str = malloc(Proc_name_max_len + 1);    // +1 = trailing '\0'
        rtos->thread_details[i].extra_info_str  = malloc(strlen(info_str) + 1);
        if (!rtos->thread_details[i].thread_name_str || !rtos->thread_details[i].extra_info_str) 
        {
            LOG_ERROR("scmRTOS> E: allocating memory for process name or extra info string");
            return ERROR_FAIL;
        }

        strcpy(rtos->thread_details[i].extra_info_str, info_str);
        snprintf(rtos->thread_details[i].thread_name_str, Proc_name_max_len + 1, "%-*s", (int)Proc_name_max_len, os_processes[i].Name);
    }
    return ERROR_OK;
}
//------------------------------------------------------------------------------

