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
//   scmRTOS support by Harry E. Zhurov, scmRTOS Team, Copyright (c) 2016
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

          
//------------------------------------------------------------------------------
static int scmRTOS_detect_rtos               (struct target *target);
static int scmRTOS_create                    (struct target *target);
static int scmRTOS_update_proc_info          (struct rtos *rtos);
static int scmRTOS_get_proc_reg_list         (struct rtos *rtos, int64_t thread_id, char **hex_reg_list);
static int scmRTOS_get_symbol_list_to_lookup (symbol_table_elem_t *symbol_list[]);
//------------------------------------------------------------------------------
//
//    General
//
#define LOG_DBG LOG_OUTPUT // LOG_DEBUG

#define TARGET_POINTER_SIZE 4
#define MAX_PROC_COUNT      31
//--------------------------------------------------------------------
//
//    OS::TKernel
//
#define CUR_PROC_PRIORITY_OFFSET  0
#define CUR_PROC_PRIORITY_SIZE    4
#define READY_PROCESS_MAP_OFFSET  (CUR_PROC_PRIORITY_OFFSET + CUR_PROC_PRIORITY_SIZE)
#define READY_PROCESS_MAP_SIZE    4
#define ISR_NEST_COUNT_OFFSET     (READY_PROCESS_MAP_OFFSET + READY_PROCESS_MAP_SIZE)
#define ISR_NEST_COUNT_SIZE       4
#define PROC_COUNT_OFFSET         (ISR_NEST_COUNT_OFFSET + ISR_NEST_COUNT_SIZE)
#define PROC_COUNT_SIZE           4
//--------------------------------------------------------------------
//
//    OS::TBaseProcess
//
#define STACK_POINTER_OFFSET      0
#define STACK_POINTER_SIZE        4
#define TIMEOUT_OFFSET            (STACK_POINTER_OFFSET + STACK_POINTER_SIZE)
#define TIMEOUT_SIZE              4
#define PRIORITY_OFFSET           (TIMEOUT_OFFSET + TIMEOUT_SIZE)
#define PRIORITY_SIZE             4

//------------------------------------------------------------------------------
//
//    Types
//
//------------------------------------------------------------------------------
enum 
{
    SID_KERNEL        = 0,
    SID_PROCESS_TABLE = 1,
    SID_IDLE_PROC     = 2
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
    
    // kernel
    const unsigned char  CurProcPriority_offset;
    const unsigned char  CurProcPriority_size;
    const unsigned char  ReadyProcessMap_offset;
    const unsigned char  ReadyProcessMap_size;
    const unsigned char  PROC_COUNT_offset;
    const unsigned char  PROC_COUNT_size;
    
    // process
    const unsigned char  StackPointer_offset;
    const unsigned char  StackPointer_size;
    const unsigned char  Timeout_offset;
    const unsigned char  Timeout_size;
    const unsigned char  Priority_offset;
    const unsigned char  Priority_size;
    
    // openocd
    const struct         rtos_register_stacking *stacking_info;
    
}
scmRTOS_params_t;
//------------------------------------------------------------------------------
typedef struct
{
    const uint32_t KernelAddr;
    const uint32_t ProcessTableAddr;
    const uint32_t IdleProcAddr;
    bool           ReversePrioOrder;
    uint32_t       ProcessTable[MAX_PROC_COUNT];
}
os_info_t;
//------------------------------------------------------------------------------
typedef struct 
{
    uint32_t CurProcPriority;
    uint32_t ReadyProcessMap;
    uint32_t PROC_COUNT;
}
os_kernel_t;
//------------------------------------------------------------------------------
typedef struct 
{
    uint32_t StackPointer;
    uint32_t Timeout;
    uint32_t Priority;
    bool     Ready;
}
os_process_t;
//------------------------------------------------------------------------------
static int get_kernel_data   (struct rtos *rtos, os_info_t *os_info, const scmRTOS_params_t *params, os_kernel_t *os_kernel);
static int get_processes_data(struct rtos *rtos, os_info_t *os_info, os_kernel_t *os_kernel, const scmRTOS_params_t *params, os_process_t*os_processes);
static int renew_proc_info   (struct rtos *rtos, os_info_t *os_info, os_kernel_t  *os_kernel, os_process_t *os_processes);
//------------------------------------------------------------------------------
//
//    Objects
//
//------------------------------------------------------------------------------
struct rtos_type scmRTOS_rtos = 
{
    .name                      = "scmRTOS",
    .detect_rtos               = scmRTOS_detect_rtos,
    .create                    = scmRTOS_create,
    .update_threads            = scmRTOS_update_proc_info,
    .get_thread_reg_list       = scmRTOS_get_proc_reg_list,
    .get_symbol_list_to_lookup = scmRTOS_get_symbol_list_to_lookup
};
//------------------------------------------------------------------------------
static const symbols_t scmRTOS_symbols[] = 
{
    { "OS::Kernel",                false },
    { "OS::TKernel::ProcessTable", false },
    { "OS::IdleProc",              false },
    { NULL,                        false }
};
//------------------------------------------------------------------------------
static const scmRTOS_params_t scmRTOS_params[] = 
{
    {
        "cortex_m",                       
        TARGET_POINTER_SIZE,
        CUR_PROC_PRIORITY_OFFSET,
        CUR_PROC_PRIORITY_SIZE,
        READY_PROCESS_MAP_OFFSET,
        READY_PROCESS_MAP_SIZE,
        PROC_COUNT_OFFSET,
        PROC_COUNT_SIZE,
        STACK_POINTER_OFFSET,
        STACK_POINTER_SIZE,
        TIMEOUT_OFFSET,
        TIMEOUT_SIZE,
        PRIORITY_OFFSET,
        PRIORITY_SIZE,
        &rtos_standard_Cortex_M3_stacking 
    }
};
//------------------------------------------------------------------------------
static uint32_t ProcessTable[MAX_PROC_COUNT];
//------------------------------------------------------------------------------
static const int TARGET_COUNT = sizeof(scmRTOS_params)/sizeof(scmRTOS_params[0]);
static const int SYMBOL_COUNT = sizeof(scmRTOS_symbols)/sizeof(scmRTOS_symbols[0]);
//------------------------------------------------------------------------------
//
//    Interface
//
//------------------------------------------------------------------------------
int scmRTOS_detect_rtos(struct target *target)
{
    if( target->rtos->symbols != NULL ) 
    {
        if( target->rtos->symbols[SID_KERNEL].address        != 0 &&
            target->rtos->symbols[SID_PROCESS_TABLE].address != 0 )
            return 1;  // looks like scmRTOS
    }
    return 0;
}
//------------------------------------------------------------------------------
int scmRTOS_create(struct target *target)
{
    int i = 0;
    
    while( (i < TARGET_COUNT) && (!strcmp(scmRTOS_params[i].target_name, target->type->name)) )
    {
        i++;
    }

    if(i >= TARGET_COUNT)
    {
        LOG_ERROR("scmRTOS> E: target does not supported");
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

    const scmRTOS_params_t *params = (const scmRTOS_params_t *)rtos->rtos_specific_params;

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

    os_info_t os_info = 
    {
        rtos->symbols[SID_KERNEL].address,
        rtos->symbols[SID_PROCESS_TABLE].address,
        rtos->symbols[SID_IDLE_PROC].address,
        false,                                      // reverse prority order
        { 0 }
    };
    
    //----------------------------------------------------------------
    //
    //    Get OS::Kernel data
    //
    os_kernel_t os_kernel;
    int res = get_kernel_data(rtos, &os_info, params, &os_kernel);
    
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not get kernel data");
        return res;
    }
    if(os_kernel.CurProcPriority > MAX_PROC_COUNT)
    {
        LOG_DBG("scmRTOS> I: RTOS does not run yet\r\n");
        return ERROR_WAIT;
    }

    //----------------------------------------------------------------
    //
    //    Get RTOS processes data
    //
    os_process_t os_processes[MAX_PROC_COUNT];
    res = get_processes_data(rtos, &os_info, &os_kernel, params, os_processes);
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not get processes data");
        return res;
    }

    rtos_free_threadlist(rtos);   // delete previous process details if any

    res = renew_proc_info(rtos, &os_info, &os_kernel, os_processes);
    if (res != ERROR_OK) 
    {
        LOG_ERROR("scmRTOS> E: could not renew processes info");
        return res;
    }
    
    rtos->thread_count = os_kernel.PROC_COUNT;
    LOG_OUTPUT("***************************************\r\n");
    LOG_OUTPUT("scmRTOS> %u processes, CurProcPriority: %d\n", os_kernel.PROC_COUNT, os_kernel.CurProcPriority);

    return ERROR_OK;
}
//------------------------------------------------------------------------------
int scmRTOS_get_proc_reg_list(struct rtos *rtos, int64_t thread_id, char **hex_reg_list)
{
    int      res;
    uint32_t stack_ptr = 0;

    *hex_reg_list = NULL;
    if (rtos == NULL)
        return -1;

    if (thread_id == 0 || thread_id > MAX_PROC_COUNT+1)
        return -2;

    if (rtos->rtos_specific_params == NULL)
        return -1;

    const scmRTOS_params_t *params = (const scmRTOS_params_t *)rtos->rtos_specific_params;
    

    uint32_t sp_addr = ProcessTable[thread_id-1] + params->StackPointer_offset;
    // Read the stack pointer
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

    return rtos_generic_stack_read(rtos->target, params->stacking_info, stack_ptr, hex_reg_list);
    
}
//------------------------------------------------------------------------------
int scmRTOS_get_symbol_list_to_lookup(symbol_table_elem_t *symbol_list[])
{
     *symbol_list = calloc( SYMBOL_COUNT, sizeof(symbol_table_elem_t) );
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
//
//    Internal Functions
//
//------------------------------------------------------------------------------
int get_kernel_data(struct rtos            *rtos, 
                    os_info_t              *os_info, 
                    const scmRTOS_params_t *params, 
                    os_kernel_t            *os_kernel)
{

    LOG_DBG("scmRTOS> get_kernel_data \r\n");
    
    uint32_t addr;
    uint32_t size;
    int      res;
    
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

    //  PROC_COUNT
    addr = os_info->KernelAddr + params->PROC_COUNT_offset;
    size = params->PROC_COUNT_size;
    res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&os_kernel->PROC_COUNT);
    if(res != ERROR_OK)
        return res;
    LOG_DBG("scmRTOS> I: PROC_COUNT at 0x%x = %d\r\n", addr, os_kernel->PROC_COUNT);
    
    if(os_kernel->PROC_COUNT > MAX_PROC_COUNT || 
       os_kernel->CurProcPriority > os_kernel->PROC_COUNT ||
       os_kernel->CurProcPriority == MAX_PROC_COUNT+1)   // os not run yet
    {
        LOG_DBG("scmRTOS> I: RTOS does not run yet\r\n");
        return ERROR_WAIT;
    }

    //  ProcessTable
    addr = os_info->ProcessTableAddr;
    size = (os_kernel->PROC_COUNT)*(params->pointer_size);
    res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&os_info->ProcessTable);
    if(res != ERROR_OK)
        return res;
    

    for(unsigned i = 0; i < os_kernel->PROC_COUNT; ++i)
    {
        LOG_DEBUG("scmRTOS> I: ProcessTable[%d]: 0x%x\r\n", i, os_info->ProcessTable[i]);
    }
    
    //  Check Reverse Priority Order
    addr = os_info->IdleProcAddr + params->Priority_offset;
    size = params->Priority_size;
    uint32_t IdleProcPriority;
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
int get_processes_data(struct rtos            *rtos, 
                       os_info_t              *os_info,
                       os_kernel_t            *os_kernel, 
                       const scmRTOS_params_t *params, 
                       os_process_t           *os_processes)
{
    LOG_DBG("scmRTOS> get_processes_data \r\n");
    for(unsigned i = 0; i < os_kernel->PROC_COUNT; ++i)
    {
        uint32_t addr;
        uint32_t size;
        uint32_t value;
        int res;
        
        uint32_t ProcAddr = os_info->ProcessTable[i];
        
        //  Stack Pointer
        addr = ProcAddr + params->StackPointer_offset;
        size = params->StackPointer_size;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        os_processes[i].StackPointer = value;

        // Timeout
        addr = ProcAddr + params->Timeout_offset;
        size = params->Timeout_size;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        os_processes[i].Timeout = value;

        // Priority
        addr = ProcAddr + params->Priority_offset;
        size = params->Priority_size;
        res  = target_read_buffer(rtos->target, addr, size, (uint8_t *)&value);
        if(res != ERROR_OK)
            return res;
        os_processes[i].Priority = value;
        
        if(os_processes[i].Priority > MAX_PROC_COUNT)
        {
            LOG_ERROR("scmRTOS> E: invalid process priority value: %d", os_processes[i].Priority);
        }

        LOG_DBG("scmRTOS> I: process index: %d at 0x%x > SP: 0x%x, Timeout: %d, Priority: %d\r\n", 
                  i, ProcAddr, 
                  os_processes[i].StackPointer, 
                  os_processes[i].Timeout,
                  os_processes[i].Priority);
    }
    return ERROR_OK;
}
//------------------------------------------------------------------------------
int renew_proc_info(struct rtos  *rtos,
                    os_info_t    *os_info,
                    os_kernel_t  *os_kernel, 
                    os_process_t *os_processes)
{
    
    LOG_DBG("scmRTOS> renew_proc_info \r\n");
    uint32_t proc_count = os_kernel->PROC_COUNT;
    rtos->thread_details = malloc( sizeof(struct thread_detail)*proc_count );
    if (!rtos->thread_details) 
    {
        LOG_ERROR("scmRTOS> E: allocating memory for %d processes", proc_count);
        return ERROR_FAIL;
    }
    
    for(unsigned i = 0; i < os_kernel->PROC_COUNT; ++i)
    {
        uint32_t ProcAddr = os_info->ProcessTable[i];
        
        // Ready-to-run
        uint32_t PrioMask = 0x00000001;
        if(os_info->ReversePrioOrder)
        {
            PrioMask <<= os_processes[i].Priority;
        }
        else
        {
            PrioMask <<= os_kernel->PROC_COUNT-1;
            PrioMask >>= os_processes[i].Priority;
        }

        os_processes[i].Ready = os_kernel->ReadyProcessMap & PrioMask;

        char Active[]    = "Active";
        char Suspended[] = "Suspended";
        char Preempted[] = "Preempted";

        char *info_str     = NULL;
        int  info_str_size = 0;

        if(os_processes[i].Ready)
        {
            if( os_kernel->CurProcPriority == os_processes[i].Priority )
            {
                rtos->current_thread = os_processes[i].Priority + 1;
                info_str             = Active;
                info_str_size        = sizeof(Active);
                LOG_DBG("scmRTOS> I: current process index %d, addr 0x%x\r\n", i, ProcAddr);
            }
            else
            {
                info_str      = Preempted;
                info_str_size = sizeof(Preempted);
            }
        }
        else
        {
            info_str      = Suspended;
            info_str_size = sizeof(Suspended);
        }

        ProcessTable[os_processes[i].Priority] = ProcAddr;
        
        rtos->thread_details[i].threadid        = os_processes[i].Priority + 1;
        rtos->thread_details[i].exists          = true;
        rtos->thread_details[i].display_str     = malloc(16);;
        rtos->thread_details[i].thread_name_str = malloc(16); //NULL;
        rtos->thread_details[i].extra_info_str  = malloc(info_str_size);
        if (!rtos->thread_details[i].extra_info_str) 
        {
            LOG_ERROR("scmRTOS> E: allocating memory for process extra info string");
            return ERROR_FAIL;
        }

        sprintf(rtos->thread_details[i].display_str, "%s %d", "Prio", os_processes[i].Priority);
        strcpy(rtos->thread_details[i].extra_info_str, info_str);

        if( (  os_info->ReversePrioOrder && os_processes[i].Priority == 0  ) ||
            ( !os_info->ReversePrioOrder && os_processes[i].Priority == os_kernel->PROC_COUNT-1) )
        {
            strcpy(rtos->thread_details[i].thread_name_str, "IdleProc");
        }
        else 
        {
            strcpy(rtos->thread_details[i].thread_name_str, "NoName  ");
        }
    }
    return ERROR_OK;
}
//------------------------------------------------------------------------------

