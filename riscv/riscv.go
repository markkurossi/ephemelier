//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"encoding/binary"
	"fmt"
)

type InstType int

const (
	RType InstType = iota
	IType
	SType
	BType
	UType
	JType
)

// RISC-V opcodes
const (
	LOAD      = 0x03
	LOAD_FP   = 0x07
	MISC_MEM  = 0x0f
	OP_IMM    = 0x13
	AUIPC     = 0x17
	OP_IMM_32 = 0x1b
	STORE     = 0x23
	AMO       = 0x2f
	OP        = 0x33
	LUI       = 0x37
	OP_32     = 0x3b
	OP_FP     = 0x53
	BRANCH    = 0x63
	JALR      = 0x67
	JAL       = 0x6f
	SYSTEM    = 0x73
)

// Instruction represents a decoded instruction (simplified)
type Instruction struct {
	Raw    uint32
	Opcode uint32
	Rd     uint32
	Rs1    uint32
	Rs2    uint32
	Funct3 uint32
	Funct7 uint32
	Imm    int32
}

// signExtend extends a value of given bit-width
func signExtend(val int32, bits int) int32 {
	shift := 32 - bits
	return (val << shift) >> shift
}

func decode(inst uint32) Instruction {
	i := Instruction{
		Raw:    inst,
		Opcode: inst & 0x7f,
		Rd:     (inst >> 7) & 0x1f,
		Funct3: (inst >> 12) & 0x7,
		Rs1:    (inst >> 15) & 0x1f,
		Rs2:    (inst >> 20) & 0x1f,
		Funct7: (inst >> 25) & 0x7f,
	}

	switch i.Opcode {

	case OP_IMM, LOAD, JALR, OP_IMM_32:
		imm := int32(inst) >> 20
		i.Imm = signExtend(imm, 12)

	case STORE:
		imm := ((inst >> 7) & 0x1f) | (((inst >> 25) & 0x7f) << 5)
		i.Imm = signExtend(int32(imm), 12)

	case BRANCH:
		imm :=
			((inst>>8)&0x0f)<<1 |
				((inst>>25)&0x3f)<<5 |
				((inst>>7)&0x1)<<11 |
				((inst >> 31) << 12)
		i.Imm = signExtend(int32(imm), 13)

	case LUI, AUIPC:
		i.Imm = int32(inst & 0xfffff000)

	case JAL:
		imm :=
			((inst>>21)&0x3ff)<<1 |
				((inst>>20)&0x1)<<11 |
				((inst>>12)&0xff)<<12 |
				((inst >> 31) << 20)
		i.Imm = signExtend(int32(imm), 21)
	}

	return i
}

func decodeAMO(i Instruction, width string) string {
	op := (i.Funct7 >> 2) & 0x1f
	aq := (i.Funct7 >> 1) & 0x1
	rl := i.Funct7 & 0x1
	suffix := ""
	if aq != 0 {
		suffix += ".aq"
	}
	if rl != 0 {
		suffix += ".rl"
	}

	switch op {
	case 0x00:
		return fmt.Sprintf("amoadd.%s%s x%d, x%d, (x%d)",
			width, suffix, i.Rd, i.Rs2, i.Rs1)
	case 0x01:
		return fmt.Sprintf("amoswap.%s%s x%d, x%d, (x%d)",
			width, suffix, i.Rd, i.Rs2, i.Rs1)
	case 0x02:
		return fmt.Sprintf("lr.%s%s x%d, (x%d)",
			width, suffix, i.Rd, i.Rs1)
	case 0x03:
		return fmt.Sprintf("sc.%s%s x%d, x%d, (x%d)",
			width, suffix, i.Rd, i.Rs2, i.Rs1)
	case 0x04:
		return fmt.Sprintf("amoxor.%s%s x%d, x%d, (x%d)",
			width, suffix, i.Rd, i.Rs2, i.Rs1)
	case 0x08:
		return fmt.Sprintf("amoor.%s%s x%d, x%d, (x%d)",
			width, suffix, i.Rd, i.Rs2, i.Rs1)
	case 0x0c:
		return fmt.Sprintf("amoand.%s%s x%d, x%d, (x%d)",
			width, suffix, i.Rd, i.Rs2, i.Rs1)
	}

	return "amo.unknown"
}

func shamt(i Instruction) uint32 {
	return (i.Raw >> 20) & 0x3f
}

func disasm(i Instruction, pc uint64) string {
	switch i.Opcode {

	// ========= LOAD =========
	case LOAD:
		switch i.Funct3 {
		case 0x0:
			return fmt.Sprintf("lb x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x1:
			return fmt.Sprintf("lh x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x2:
			return fmt.Sprintf("lw x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x3:
			return fmt.Sprintf("ld x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x4:
			return fmt.Sprintf("lbu x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x5:
			return fmt.Sprintf("lhu x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x6:
			return fmt.Sprintf("lwu x%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		}

	case LOAD_FP:
		switch i.Funct3 {
		case 0x2:
			return fmt.Sprintf("flw f%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		case 0x3:
			return fmt.Sprintf("fld f%d, %d(x%d)", i.Rd, i.Imm, i.Rs1)
		}

	case MISC_MEM:
		return fmt.Sprintf("fence (raw=0x%x)", i.Raw)

	// ========= STORE =========
	case STORE:
		switch i.Funct3 {
		case 0x0:
			return fmt.Sprintf("sb x%d, %d(x%d)", i.Rs2, i.Imm, i.Rs1)
		case 0x1:
			return fmt.Sprintf("sh x%d, %d(x%d)", i.Rs2, i.Imm, i.Rs1)
		case 0x2:
			return fmt.Sprintf("sw x%d, %d(x%d)", i.Rs2, i.Imm, i.Rs1)
		case 0x3:
			return fmt.Sprintf("sd x%d, %d(x%d)", i.Rs2, i.Imm, i.Rs1)
		}

	// ========= OP-IMM =========
	case OP_IMM:
		switch i.Funct3 {
		case 0x0:
			return fmt.Sprintf("addi x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)
		case 0x2:
			return fmt.Sprintf("slti x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)
		case 0x3:
			return fmt.Sprintf("sltiu x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)
		case 0x4:
			return fmt.Sprintf("xori x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)
		case 0x6:
			return fmt.Sprintf("ori x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)
		case 0x7:
			return fmt.Sprintf("andi x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)
		case 0x1:
			return fmt.Sprintf("slli x%d, x%d, %d", i.Rd, i.Rs1, shamt(i))
		case 0x5:
			if i.Funct7 == 0x00 {
				return fmt.Sprintf("srli x%d, x%d, %d", i.Rd, i.Rs1, shamt(i))
			} else if i.Funct7 == 0x20 {
				return fmt.Sprintf("srai x%d, x%d, %d", i.Rd, i.Rs1, shamt(i))
			}
		}

	// === AMO ===
	case AMO:
		switch i.Funct3 {
		case 0x2: // word
			return decodeAMO(i, "w")
		case 0x3: // double
			return decodeAMO(i, "d")
		}

		// ========= OP =========
	case OP:
		// ---- M extension (mul/div) ----
		if i.Funct7 == 0x01 {
			switch i.Funct3 {
			case 0x0:
				return fmt.Sprintf("mul x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x1:
				return fmt.Sprintf("mulh x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x2:
				return fmt.Sprintf("mulhsu x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x3:
				return fmt.Sprintf("mulhu x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x4:
				return fmt.Sprintf("div x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x5:
				return fmt.Sprintf("divu x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x6:
				return fmt.Sprintf("rem x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x7:
				return fmt.Sprintf("remu x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			}
		}

		// ---- Base integer ops ----
		switch i.Funct3 {
		case 0x0:
			if i.Funct7 == 0x00 {
				return fmt.Sprintf("add x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			} else if i.Funct7 == 0x20 {
				return fmt.Sprintf("sub x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			}
		case 0x1:
			return fmt.Sprintf("sll x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		case 0x2:
			return fmt.Sprintf("slt x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		case 0x3:
			return fmt.Sprintf("sltu x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		case 0x4:
			return fmt.Sprintf("xor x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		case 0x5:
			if i.Funct7 == 0x00 {
				return fmt.Sprintf("srl x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			} else if i.Funct7 == 0x20 {
				return fmt.Sprintf("sra x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			}
		case 0x6:
			return fmt.Sprintf("or x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		case 0x7:
			return fmt.Sprintf("and x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		}

	// ========= BRANCH =========
	case BRANCH:
		target := pc + uint64(int64(i.Imm))
		switch i.Funct3 {
		case 0x0:
			return fmt.Sprintf("beq x%d, x%d, 0x%x", i.Rs1, i.Rs2, target)
		case 0x1:
			return fmt.Sprintf("bne x%d, x%d, 0x%x", i.Rs1, i.Rs2, target)
		case 0x4:
			return fmt.Sprintf("blt x%d, x%d, 0x%x", i.Rs1, i.Rs2, target)
		case 0x5:
			return fmt.Sprintf("bge x%d, x%d, 0x%x", i.Rs1, i.Rs2, target)
		case 0x6:
			return fmt.Sprintf("bltu x%d, x%d, 0x%x", i.Rs1, i.Rs2, target)
		case 0x7:
			return fmt.Sprintf("bgeu x%d, x%d, 0x%x", i.Rs1, i.Rs2, target)
		}

	// ========= JUMPS =========
	case JAL:
		return fmt.Sprintf("jal x%d, 0x%x", i.Rd, pc+uint64(i.Imm))

	case JALR:
		return fmt.Sprintf("jalr x%d, %d(x%d) & ~1", i.Rd, i.Imm, i.Rs1)

	// ========= U-TYPE =========
	case LUI:
		return fmt.Sprintf("lui x%d, 0x%x", i.Rd, i.Imm)

	case OP_32:
		switch i.Funct3 {
		case 0x0:
			if i.Funct7 == 0x00 {
				return fmt.Sprintf("addw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			} else if i.Funct7 == 0x20 {
				return fmt.Sprintf("subw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			}
		case 0x1:
			return fmt.Sprintf("sllw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
		case 0x5:
			if i.Funct7 == 0x00 {
				return fmt.Sprintf("srlw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			} else if i.Funct7 == 0x20 {
				return fmt.Sprintf("sraw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			}
		}
		if i.Funct7 == 0x01 {
			switch i.Funct3 {
			case 0x0:
				return fmt.Sprintf("mulw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x4:
				return fmt.Sprintf("divw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x5:
				return fmt.Sprintf("divuw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x6:
				return fmt.Sprintf("remw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			case 0x7:
				return fmt.Sprintf("remuw x%d, x%d, x%d", i.Rd, i.Rs1, i.Rs2)
			}
		}

	case OP_FP:
		switch i.Funct7 {
		case 0x00:
			return fmt.Sprintf("fadd.s f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)
		case 0x01:
			return fmt.Sprintf("fadd.d f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)
		case 0x04:
			return fmt.Sprintf("fsub.s f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)
		case 0x05:
			return fmt.Sprintf("fsub.d f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)
		case 0x10:
			return fmt.Sprintf("fsgnj.s f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)
		case 0x11:
			return fmt.Sprintf("fsgnj.d f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)

		case 0x14:
			return fmt.Sprintf("fmin.s f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)
		case 0x15:
			return fmt.Sprintf("fmin.d f%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)

		case 0x50:
			return fmt.Sprintf("feq.s x%d, f%d, f%d", i.Rd, i.Rs1, i.Rs2)

		case 0x60:
			return fmt.Sprintf("fcvt.w.s x%d, f%d", i.Rd, i.Rs1)
		case 0x61:
			return fmt.Sprintf("fcvt.w.d x%d, f%d", i.Rd, i.Rs1)
		}

	case AUIPC:
		return fmt.Sprintf("auipc x%d, 0x%x", i.Rd, i.Imm)

	case OP_IMM_32:
		switch i.Funct3 {
		case 0x0:
			return fmt.Sprintf("addiw x%d, x%d, %d", i.Rd, i.Rs1, i.Imm)

		case 0x1: // SLLIW
			shamt := (i.Raw >> 20) & 0x1f // 5-bit!
			return fmt.Sprintf("slliw x%d, x%d, %d", i.Rd, i.Rs1, shamt)

		case 0x5:
			shamt := (i.Raw >> 20) & 0x1f

			if i.Funct7 == 0x00 {
				return fmt.Sprintf("srliw x%d, x%d, %d", i.Rd, i.Rs1, shamt)
			} else if i.Funct7 == 0x20 {
				return fmt.Sprintf("sraiw x%d, x%d, %d", i.Rd, i.Rs1, shamt)
			}
		}

		// ========= SYSTEM =========
	case SYSTEM:
		switch i.Funct3 {
		case 0x1:
			return fmt.Sprintf("csrrw x%d, csr, x%d", i.Rd, i.Rs1)
		case 0x2:
			return fmt.Sprintf("csrrs x%d, csr, x%d", i.Rd, i.Rs1)
		case 0x3:
			return fmt.Sprintf("csrrc x%d, csr, x%d", i.Rd, i.Rs1)
		case 0x5:
			return fmt.Sprintf("csrrwi x%d, csr, %d", i.Rd, i.Rs1)
		case 0x6:
			return fmt.Sprintf("csrrsi x%d, csr, %d", i.Rd, i.Rs1)
		case 0x7:
			return fmt.Sprintf("csrrci x%d, csr, %d", i.Rd, i.Rs1)
		}

		if i.Raw == 0x00000073 {
			return "ecall"
		}
		if i.Raw == 0x00100073 {
			return "ebreak"
		}
	}

	return fmt.Sprintf("unknown 0x%08x opcode=0x%x f3=0x%x f7=0x%x",
		i.Raw, i.Opcode, i.Funct3, i.Funct7)
}

func disasmC(inst uint32, pc uint64) string {
	op := inst & 0x3
	funct3 := (inst >> 13) & 0x7

	switch op {

	case 0x0:
		switch funct3 {
		case 0x0:
			return "c.addi4spn"
		case 0x2:
			return "c.lw"
		case 0x3:
			return "c.ld"
		}

	case 0x1:
		switch funct3 {
		case 0x0:
			return "c.addi"
		case 0x2:
			return "c.li"
		case 0x3:
			return "c.lui"
		case 0x5:
			return "c.j"
		case 0x6:
			return "c.beqz"
		case 0x7:
			return "c.bnez"
		}

	case 0x2:
		switch funct3 {
		case 0x0:
			return "c.slli"
		case 0x2:
			return "c.lwsp"
		case 0x3:
			return "c.ldsp"
		case 0x4:
			return "c.mv/add"
		case 0x6:
			return "c.swsp"
		case 0x7:
			return "c.sdsp"
		}
	}

	return "c.unknown"
}

func decodeStream(data []byte, pc uint64) {
	for i := 0; i < len(data); {
		half := binary.LittleEndian.Uint16(data[i:])

		if half&0x3 != 0x3 {
			if i+2 > len(data) {
				break
			}
			// ---- 16-bit compressed ----
			inst := uint32(half)
			fmt.Printf("0x%x:\t%04x\t%s\n",
				pc+uint64(i),
				half,
				disasmC(inst, pc+uint64(i)),
			)
			i += 2
		} else {
			// ---- 32-bit normal ----
			inst := binary.LittleEndian.Uint32(data[i:])
			decoded := decode(inst)

			fmt.Printf("0x%x:\t%08x\t%s\n",
				pc+uint64(i),
				inst,
				disasm(decoded, pc+uint64(i)),
			)
			i += 4
		}
	}
}
