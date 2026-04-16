use alloc::vec::Vec;
use core::slice;

use crate::interrupts::{Aarch64GicModel, Aarch64InterruptConfig};
use crate::virtio_mmio::{DiscoveredInterrupt, DiscoveredMmioDevice};

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 0x1;
const FDT_END_NODE: u32 = 0x2;
const FDT_PROP: u32 = 0x3;
const FDT_NOP: u32 = 0x4;
const FDT_END: u32 = 0x9;

const COMPAT_GIC_V3: u8 = 1 << 0;
const COMPAT_GIC_V2: u8 = 1 << 1;
const COMPAT_TIMER: u8 = 1 << 2;
const COMPAT_VIRTIO_MMIO: u8 = 1 << 3;

#[derive(Clone, Copy)]
struct Region {
    base: u64,
    size: u64,
}

impl Region {
    const fn empty() -> Self {
        Self { base: 0, size: 0 }
    }
}

#[derive(Clone, Copy)]
struct PropertyRef {
    offset: usize,
    len: usize,
}

#[derive(Clone, Copy)]
struct ControllerInfo {
    phandle: u32,
    interrupt_cells: u32,
    compatible: u8,
}

#[derive(Clone, Copy)]
struct ControllerNode {
    phandle: u32,
    interrupt_cells: u32,
    compatible: u8,
    is_interrupt_controller: bool,
}

impl ControllerNode {
    const fn new() -> Self {
        Self {
            phandle: 0,
            interrupt_cells: 0,
            compatible: 0,
            is_interrupt_controller: false,
        }
    }
}

#[derive(Clone, Copy)]
struct NodeState {
    parent_address_cells: u32,
    parent_size_cells: u32,
    child_address_cells: u32,
    child_size_cells: u32,
    compatible: u8,
    disabled: bool,
    clock_frequency_hz: Option<u64>,
    effective_interrupt_parent: Option<u32>,
    regions: [Region; 4],
    region_count: usize,
    interrupts: [DiscoveredInterrupt; 4],
    interrupt_count: usize,
    interrupts_prop: Option<PropertyRef>,
    interrupts_extended_prop: Option<PropertyRef>,
}

impl NodeState {
    fn new(
        parent_address_cells: u32,
        parent_size_cells: u32,
        effective_interrupt_parent: Option<u32>,
    ) -> Self {
        Self {
            parent_address_cells,
            parent_size_cells,
            child_address_cells: parent_address_cells,
            child_size_cells: parent_size_cells,
            compatible: 0,
            disabled: false,
            clock_frequency_hz: None,
            effective_interrupt_parent,
            regions: [Region::empty(); 4],
            region_count: 0,
            interrupts: [DiscoveredInterrupt::empty(); 4],
            interrupt_count: 0,
            interrupts_prop: None,
            interrupts_extended_prop: None,
        }
    }
}

pub struct DeviceTreeInfo {
    pub interrupt_model: Option<Aarch64InterruptConfig>,
    pub virtio_mmio: Vec<DiscoveredMmioDevice>,
}

pub fn parse(dtb_addr: u64) -> Option<DeviceTreeInfo> {
    if dtb_addr == 0 {
        return None;
    }

    let totalsize = read_be32(
        unsafe { slice::from_raw_parts(dtb_addr as *const u8, 8) },
        4,
    )? as usize;
    let blob = unsafe { slice::from_raw_parts(dtb_addr as *const u8, totalsize) };
    let header = FdtHeader::parse(blob)?;
    let structure = blob.get(header.off_dt_struct..header.off_dt_struct + header.size_dt_struct)?;
    let strings =
        blob.get(header.off_dt_strings..header.off_dt_strings + header.size_dt_strings)?;
    let controllers = collect_interrupt_controllers(structure, strings)?;

    let mut stack = Vec::new();
    let mut offset = 0usize;
    let mut gic = None;
    let mut timer = None;
    let mut timer_frequency_hz = None;
    let mut virtio_mmio = Vec::new();

    while offset + 4 <= structure.len() {
        let token = read_be32(structure, offset)?;
        offset += 4;

        match token {
            FDT_BEGIN_NODE => {
                let (parent_address_cells, parent_size_cells, effective_interrupt_parent) = stack
                    .last()
                    .map(|state: &NodeState| {
                        (
                            state.child_address_cells,
                            state.child_size_cells,
                            state.effective_interrupt_parent,
                        )
                    })
                    .unwrap_or((2, 1, None));
                stack.push(NodeState::new(
                    parent_address_cells,
                    parent_size_cells,
                    effective_interrupt_parent,
                ));
                while offset < structure.len() && structure[offset] != 0 {
                    offset += 1;
                }
                if offset >= structure.len() {
                    return None;
                }
                offset = align4(offset + 1);
            }
            FDT_END_NODE => {
                let mut node = stack.pop()?;
                if node.disabled {
                    continue;
                }

                if let Some(prop) = node.interrupts_extended_prop {
                    let data = structure.get(prop.offset..prop.offset + prop.len)?;
                    node.interrupt_count =
                        parse_interrupts_extended(data, &controllers, &mut node.interrupts);
                } else if let Some(prop) = node.interrupts_prop {
                    let data = structure.get(prop.offset..prop.offset + prop.len)?;
                    node.interrupt_count = parse_interrupts(
                        data,
                        node.effective_interrupt_parent,
                        &controllers,
                        &mut node.interrupts,
                    );
                }

                if gic.is_none() && (node.compatible & COMPAT_GIC_V3) != 0 && node.region_count >= 2
                {
                    gic = Some(Aarch64InterruptConfig {
                        gic_model: Aarch64GicModel::V3,
                        gicd_base: node.regions[0].base,
                        gicr_base: node.regions[1].base,
                        gicc_base: 0,
                        timer_intid: 0,
                        timer_edge_triggered: false,
                        counter_frequency_hz: None,
                    });
                } else if gic.is_none()
                    && (node.compatible & COMPAT_GIC_V2) != 0
                    && node.region_count >= 2
                {
                    gic = Some(Aarch64InterruptConfig {
                        gic_model: Aarch64GicModel::V2,
                        gicd_base: node.regions[0].base,
                        gicr_base: 0,
                        gicc_base: node.regions[1].base,
                        timer_intid: 0,
                        timer_edge_triggered: false,
                        counter_frequency_hz: None,
                    });
                }

                if timer.is_none()
                    && (node.compatible & COMPAT_TIMER) != 0
                    && node.interrupt_count != 0
                {
                    let timer_index = if node.interrupt_count > 1 { 1 } else { 0 };
                    timer = Some(node.interrupts[timer_index]);
                    timer_frequency_hz = node.clock_frequency_hz;
                }

                if (node.compatible & COMPAT_VIRTIO_MMIO) != 0 && node.region_count != 0 {
                    let interrupt = if node.interrupt_count != 0 {
                        Some(node.interrupts[0])
                    } else {
                        None
                    };
                    virtio_mmio.push(DiscoveredMmioDevice {
                        base: node.regions[0].base,
                        size: node.regions[0].size,
                        interrupt,
                    });
                }
            }
            FDT_PROP => {
                let len = read_be32(structure, offset)? as usize;
                let nameoff = read_be32(structure, offset + 4)? as usize;
                offset += 8;
                let data = structure.get(offset..offset + len)?;
                let prop = PropertyRef { offset, len };
                offset = align4(offset + len);

                let name = string_at(strings, nameoff)?;
                let state = stack.last_mut()?;
                match name {
                    b"compatible" => state.compatible = parse_compatible(data),
                    b"status" => state.disabled = is_disabled(data),
                    b"#address-cells" => {
                        if let Some(value) = parse_u32(data) {
                            state.child_address_cells = value;
                        }
                    }
                    b"#size-cells" => {
                        if let Some(value) = parse_u32(data) {
                            state.child_size_cells = value;
                        }
                    }
                    b"clock-frequency" => {
                        state.clock_frequency_hz = parse_u32(data).map(u64::from);
                    }
                    b"interrupt-parent" => {
                        state.effective_interrupt_parent = parse_u32(data);
                    }
                    b"reg" => {
                        state.region_count = parse_regions(
                            data,
                            state.parent_address_cells,
                            state.parent_size_cells,
                            &mut state.regions,
                        );
                    }
                    b"interrupts" => state.interrupts_prop = Some(prop),
                    b"interrupts-extended" => state.interrupts_extended_prop = Some(prop),
                    _ => {}
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => return None,
        }
    }

    let interrupt_model = match (gic, timer) {
        (Some(mut config), Some(timer_spec)) => {
            config.timer_intid = timer_spec.intid;
            config.timer_edge_triggered = timer_spec.edge_triggered;
            config.counter_frequency_hz = timer_frequency_hz;
            Some(config)
        }
        _ => None,
    };

    Some(DeviceTreeInfo {
        interrupt_model,
        virtio_mmio,
    })
}

fn collect_interrupt_controllers(structure: &[u8], strings: &[u8]) -> Option<Vec<ControllerInfo>> {
    let mut stack = Vec::new();
    let mut controllers = Vec::new();
    let mut offset = 0usize;

    while offset + 4 <= structure.len() {
        let token = read_be32(structure, offset)?;
        offset += 4;

        match token {
            FDT_BEGIN_NODE => {
                stack.push(ControllerNode::new());
                while offset < structure.len() && structure[offset] != 0 {
                    offset += 1;
                }
                if offset >= structure.len() {
                    return None;
                }
                offset = align4(offset + 1);
            }
            FDT_END_NODE => {
                let node = stack.pop()?;
                if node.is_interrupt_controller && node.phandle != 0 && node.interrupt_cells != 0 {
                    controllers.push(ControllerInfo {
                        phandle: node.phandle,
                        interrupt_cells: node.interrupt_cells,
                        compatible: node.compatible,
                    });
                }
            }
            FDT_PROP => {
                let len = read_be32(structure, offset)? as usize;
                let nameoff = read_be32(structure, offset + 4)? as usize;
                offset += 8;
                let data = structure.get(offset..offset + len)?;
                offset = align4(offset + len);

                let name = string_at(strings, nameoff)?;
                let node = stack.last_mut()?;
                match name {
                    b"compatible" => node.compatible = parse_compatible(data),
                    b"#interrupt-cells" => {
                        if let Some(value) = parse_u32(data) {
                            node.interrupt_cells = value;
                        }
                    }
                    b"phandle" | b"linux,phandle" => {
                        if let Some(value) = parse_u32(data) {
                            node.phandle = value;
                        }
                    }
                    b"interrupt-controller" => node.is_interrupt_controller = true,
                    _ => {}
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => return None,
        }
    }

    Some(controllers)
}

struct FdtHeader {
    off_dt_struct: usize,
    off_dt_strings: usize,
    size_dt_strings: usize,
    size_dt_struct: usize,
}

impl FdtHeader {
    fn parse(blob: &[u8]) -> Option<Self> {
        if read_be32(blob, 0)? != FDT_MAGIC {
            return None;
        }

        let totalsize = read_be32(blob, 4)? as usize;
        if totalsize > blob.len() {
            return None;
        }

        let off_dt_struct = read_be32(blob, 8)? as usize;
        let off_dt_strings = read_be32(blob, 12)? as usize;
        let size_dt_strings = read_be32(blob, 32)? as usize;
        let size_dt_struct = read_be32(blob, 36)? as usize;
        if off_dt_struct.checked_add(size_dt_struct)? > blob.len() {
            return None;
        }
        if off_dt_strings.checked_add(size_dt_strings)? > blob.len() {
            return None;
        }

        Some(Self {
            off_dt_struct,
            off_dt_strings,
            size_dt_strings,
            size_dt_struct,
        })
    }
}

fn parse_compatible(data: &[u8]) -> u8 {
    let mut compatible = 0u8;
    if contains_string(data, b"arm,gic-v3") {
        compatible |= COMPAT_GIC_V3;
    }
    if [
        b"arm,arm1176jzf-devchip-gic".as_slice(),
        b"arm,arm11mp-gic".as_slice(),
        b"arm,cortex-a15-gic".as_slice(),
        b"arm,cortex-a7-gic".as_slice(),
        b"arm,cortex-a9-gic".as_slice(),
        b"arm,eb11mp-gic".as_slice(),
        b"arm,gic-400".as_slice(),
        b"arm,pl390".as_slice(),
        b"arm,tc11mp-gic".as_slice(),
        b"brcm,brahma-b15-gic".as_slice(),
        b"nvidia,tegra210-agic".as_slice(),
        b"qcom,msm-8660-qgic".as_slice(),
        b"qcom,msm-qgic2".as_slice(),
    ]
    .iter()
    .any(|needle| contains_string(data, needle))
    {
        compatible |= COMPAT_GIC_V2;
    }
    if contains_string(data, b"arm,armv8-timer") || contains_string(data, b"arm,armv7-timer") {
        compatible |= COMPAT_TIMER;
    }
    if contains_string(data, b"virtio,mmio") {
        compatible |= COMPAT_VIRTIO_MMIO;
    }
    compatible
}

fn contains_string(data: &[u8], needle: &[u8]) -> bool {
    data.split(|b| *b == 0).any(|entry| entry == needle)
}

fn is_disabled(data: &[u8]) -> bool {
    data.starts_with(b"disabled")
}

fn parse_u32(data: &[u8]) -> Option<u32> {
    Some(read_be32(data, 0)?)
}

fn parse_regions(data: &[u8], address_cells: u32, size_cells: u32, out: &mut [Region; 4]) -> usize {
    let stride = (address_cells + size_cells) as usize * 4;
    if stride == 0 {
        return 0;
    }

    let mut count = 0usize;
    let mut offset = 0usize;
    while offset + stride <= data.len() && count < out.len() {
        let base = match read_cells(data, offset, address_cells) {
            Some(base) => base,
            None => break,
        };
        let size = match read_cells(data, offset + address_cells as usize * 4, size_cells) {
            Some(size) => size,
            None => break,
        };
        out[count] = Region { base, size };
        count += 1;
        offset += stride;
    }
    count
}

fn parse_interrupts(
    data: &[u8],
    interrupt_parent: Option<u32>,
    controllers: &[ControllerInfo],
    out: &mut [DiscoveredInterrupt; 4],
) -> usize {
    if let Some(parent) = interrupt_parent {
        if let Some(controller) = find_controller(controllers, parent) {
            return parse_interrupt_specifiers(data, controller, out);
        }
    }
    parse_interrupts_heuristic(data, out)
}

fn parse_interrupts_extended(
    data: &[u8],
    controllers: &[ControllerInfo],
    out: &mut [DiscoveredInterrupt; 4],
) -> usize {
    let mut count = 0usize;
    let mut offset = 0usize;
    while offset + 4 <= data.len() && count < out.len() {
        let phandle = match read_be32(data, offset) {
            Some(value) => value,
            None => break,
        };
        offset += 4;
        let controller = match find_controller(controllers, phandle) {
            Some(controller) => controller,
            None => break,
        };
        let spec_len = controller.interrupt_cells as usize * 4;
        if spec_len == 0 || offset + spec_len > data.len() {
            break;
        }
        if let Some(interrupt) = decode_interrupt(controller, &data[offset..offset + spec_len]) {
            out[count] = interrupt;
            count += 1;
        }
        offset += spec_len;
    }
    count
}

fn parse_interrupt_specifiers(
    data: &[u8],
    controller: ControllerInfo,
    out: &mut [DiscoveredInterrupt; 4],
) -> usize {
    let spec_len = controller.interrupt_cells as usize * 4;
    if spec_len == 0 {
        return 0;
    }

    let mut count = 0usize;
    let mut offset = 0usize;
    while offset + spec_len <= data.len() && count < out.len() {
        if let Some(interrupt) = decode_interrupt(controller, &data[offset..offset + spec_len]) {
            out[count] = interrupt;
            count += 1;
        }
        offset += spec_len;
    }
    count
}

fn decode_interrupt(controller: ControllerInfo, spec: &[u8]) -> Option<DiscoveredInterrupt> {
    if (controller.compatible & (COMPAT_GIC_V2 | COMPAT_GIC_V3)) != 0
        && controller.interrupt_cells >= 3
    {
        let int_type = read_be32(spec, 0)?;
        let number = read_be32(spec, 4)?;
        let flags = read_be32(spec, 8)?;
        let intid = match int_type {
            0 => 32 + number,
            1 => 16 + number,
            _ => number,
        };
        return Some(DiscoveredInterrupt {
            intid,
            edge_triggered: flags_edge_triggered(flags),
        });
    }

    if controller.interrupt_cells >= 2 {
        return Some(DiscoveredInterrupt {
            intid: read_be32(spec, 0)?,
            edge_triggered: flags_edge_triggered(read_be32(spec, 4)?),
        });
    }

    Some(DiscoveredInterrupt {
        intid: read_be32(spec, 0)?,
        edge_triggered: false,
    })
}

fn parse_interrupts_heuristic(data: &[u8], out: &mut [DiscoveredInterrupt; 4]) -> usize {
    if data.is_empty() {
        return 0;
    }

    if data.len() % 12 == 0 {
        let mut count = 0usize;
        let mut offset = 0usize;
        while offset + 12 <= data.len() && count < out.len() {
            let int_type = match read_be32(data, offset) {
                Some(value) => value,
                None => break,
            };
            let number = match read_be32(data, offset + 4) {
                Some(value) => value,
                None => break,
            };
            let flags = match read_be32(data, offset + 8) {
                Some(value) => value,
                None => break,
            };
            let intid = match int_type {
                0 => 32 + number,
                1 => 16 + number,
                _ => number,
            };
            out[count] = DiscoveredInterrupt {
                intid,
                edge_triggered: flags_edge_triggered(flags),
            };
            count += 1;
            offset += 12;
        }
        return count;
    }

    if data.len() % 8 == 0 {
        let mut count = 0usize;
        let mut offset = 0usize;
        while offset + 8 <= data.len() && count < out.len() {
            let intid = match read_be32(data, offset) {
                Some(value) => value,
                None => break,
            };
            let flags = match read_be32(data, offset + 4) {
                Some(value) => value,
                None => break,
            };
            out[count] = DiscoveredInterrupt {
                intid,
                edge_triggered: flags_edge_triggered(flags),
            };
            count += 1;
            offset += 8;
        }
        return count;
    }

    let mut count = 0usize;
    let mut offset = 0usize;
    while offset + 4 <= data.len() && count < out.len() {
        let intid = match read_be32(data, offset) {
            Some(value) => value,
            None => break,
        };
        out[count] = DiscoveredInterrupt {
            intid,
            edge_triggered: false,
        };
        count += 1;
        offset += 4;
    }
    count
}

fn find_controller(controllers: &[ControllerInfo], phandle: u32) -> Option<ControllerInfo> {
    controllers
        .iter()
        .copied()
        .find(|controller| controller.phandle == phandle)
}

fn flags_edge_triggered(flags: u32) -> bool {
    matches!(flags & 0x0f, 0x1..=0x3)
}

fn read_cells(data: &[u8], offset: usize, cells: u32) -> Option<u64> {
    if cells == 0 {
        return Some(0);
    }
    if cells > 2 {
        return None;
    }

    let mut value = 0u64;
    for cell in 0..cells as usize {
        value = (value << 32) | u64::from(read_be32(data, offset + cell * 4)?);
    }
    Some(value)
}

fn string_at<'a>(strings: &'a [u8], offset: usize) -> Option<&'a [u8]> {
    let tail = strings.get(offset..)?;
    let len = tail.iter().position(|b| *b == 0)?;
    Some(&tail[..len])
}

fn read_be32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

const fn align4(offset: usize) -> usize {
    (offset + 3) & !3
}
