/***************************************************************************
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

#include "rtos_scmRTOS_stackings.h"
#include "rtos_standard_stackings.h"

static const struct stack_register_offset rtos_scmRTOS_arm7tdmi_stack_offsets[] = {
	{ 0,  0x08, 32 },		/* r0   */
	{ 1,  0x0C, 32 },		/* r1   */
	{ 2,  0x10, 32 },		/* r2   */
	{ 3,  0x14, 32 },		/* r3   */
	{ 4,  0x18, 32 },		/* r4   */
	{ 5,  0x1C, 32 },		/* r5   */
	{ 6,  0x20, 32 },		/* r6   */
	{ 7,  0x24, 32 },		/* r7   */
	{ 8,  0x28, 32 },		/* r8   */
	{ 9,  0x2C, 32 },		/* r9   */
	{ 10, 0x30, 32 },		/* r10  */
	{ 11, 0x34, 32 },		/* r11  */
	{ 12, 0x38, 32 },		/* r12  */
	{ 13, -2,   32 },		/* sp   */
	{ 14, 0x04, 32 },		/* lr   */
	{ 15, 0x3C, 32 },		/* pc   */
	{ 16, 0x00, 32 },		/* xPSR */
};

const struct rtos_register_stacking rtos_scmRTOS_arm7tdmi_stacking = {
	.stack_registers_size = 16 * 4,
	.stack_growth_direction = -1,
	.num_output_registers = sizeof(rtos_scmRTOS_arm7tdmi_stack_offsets) / sizeof(rtos_scmRTOS_arm7tdmi_stack_offsets[0]),	/* num_output_registers */
	.calculate_process_stack = rtos_generic_stack_align8,
	.register_offsets = rtos_scmRTOS_arm7tdmi_stack_offsets
};
