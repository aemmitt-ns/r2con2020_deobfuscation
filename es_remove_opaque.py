from esilsolve import ESILSolver
import r2pipe

# run r2 -i es_remove_opaque.py samples/ac3e087e43be67bdc674747c665b46c2
# will take ~20 seconds
esilsolver = ESILSolver(r2pipe.open())
esilsolver.r2pipe.cmd("e anal.depth=9999")
esilsolver.r2pipe.cmd("s 0x00491aa0; af")
blocks = esilsolver.r2pipe.cmdj("afbj")

for block in blocks:
    if "jump" not in block: continue

    instrs = esilsolver.r2pipe.cmdj("pdbj @ %d" % block["addr"])
    jump_addr = instrs[-1]["offset"]
    end = block["addr"] + block["size"]
    state = esilsolver.blank_state(block["addr"])

    try:
        state = esilsolver.run(target=jump_addr, avoid=[end])
        states = state.step() # exec the jump

        if len(states) == 1:
            state = states[0]            
            if state.registers["PC"].as_long() == end:
                esilsolver.r2pipe.cmd("aho nop @ %d" % jump_addr)
            else:
                esilsolver.r2pipe.cmd("aho jmp @ %d" % jump_addr)

    except Exception as e:
        pass # a couple errors happen, nbd

esilsolver.r2pipe.cmd("af-; af") # reanalyze

