import pytest
from pathlib import Path


@pytest.fixture
def sample_trace_alu_path():
    """Return path to the ALU-only sample trace fixture."""
    return Path(__file__).parent / "fixtures" / "sample_trace_alu.log"


@pytest.fixture
def sample_trace_load_path():
    """Return path to the load with cross-tick write sample trace fixture."""
    return Path(__file__).parent / "fixtures" / "sample_trace_load.log"


@pytest.fixture
def sample_trace_branch_path():
    """Return path to the branch without D= field sample trace fixture."""
    return Path(__file__).parent / "fixtures" / "sample_trace_branch.log"


@pytest.fixture
def sample_trace_mixed_path():
    """Return path to the mixed instruction sample trace fixture."""
    return Path(__file__).parent / "fixtures" / "sample_trace_mixed.log"


@pytest.fixture
def sample_elf_path():
    """Return path to the sample softmax RISC-V ELF."""
    return Path(__file__).parent.parent.parent / "programs" / "softmax_256" / "softmax_256.riscv"
