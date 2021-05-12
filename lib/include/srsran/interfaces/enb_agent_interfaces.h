/**
 * Copyright 2013-2021 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#ifndef SRSRAN_ENB_AGENT_INTERFACES_H
#define SRSRAN_ENB_AGENT_INTERFACES_H

#include "srsran/common/byte_buffer.h"
#include "srsran/interfaces/enb_rrc_interface_types.h"

namespace srsenb {

// RRC interface for Stack
class rrc_interface_stack
{
public:
  virtual void rrc_meas_config_add(uint16_t rnti, uint8_t id, uint16_t pci, uint32_t carrier_freq, asn1::rrc::report_cfg_eutra_s::report_amount_e_ amount, asn1::rrc::report_interv_e interval) = 0;
  virtual void rrc_meas_config_rem(uint16_t rnti, uint8_t id) = 0;
};

// Agent interface for RRC
class agent_interface_rrc
{
public:
  virtual void add_user(uint64_t imsi, uint32_t tmsi, uint16_t rnti) = 0;
  virtual void rem_user(uint16_t rnti) = 0;
  virtual void handle_ue_meas_report(uint16_t rnti, const asn1::rrc::meas_report_s& msg) = 0;
};

// Agent interface for MAC
class agent_interface_mac
{
public:
  virtual void update_dl_mac_prb_utilization_report(srsenb::sched_interface::dl_sched_res_t * sched) = 0;
  virtual void update_ul_mac_prb_utilization_report(srsenb::sched_interface::ul_sched_res_t * sched) = 0;
};

class stack_interface_agent
{
public:
  virtual void rrc_meas_config_add(uint16_t rnti, uint8_t id, uint16_t pci, uint32_t carrier_freq, asn1::rrc::report_cfg_eutra_s::report_amount_e_ amount, asn1::rrc::report_interv_e interval) = 0;
  virtual void rrc_meas_config_rem(uint16_t rnti, uint8_t id) = 0;
};

} // namespace srsenb

#endif // SRSRAN_ENB_RLC_INTERFACES_H
