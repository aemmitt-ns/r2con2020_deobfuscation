from esilsolve import ESILSolver
import r2pipe

# run r2 -i es_remove_opaque.py samples/ac3e087e43be67bdc674747c665b46c2
esilsolver = ESILSolver(r2pipe.open(), debug=False)
esilsolver.r2pipe.cmd("e anal.depth=9999")
esilsolver.r2pipe.cmd("s 0x00491aa0; af")
blocks = esilsolver.r2pipe.cmdj("afbj")

block_dict = dict([(b["addr"], b) for b in blocks])
block_list = blocks[:1] # just get first block now
completed_blocks = {}

while len(block_list) > 0:
    block = block_list.pop()

    if block["addr"] not in completed_blocks:
        completed_blocks[block["addr"]] = 1
    else:
        continue

    #print("block addr: %016x" % block["addr"])
    if "jump" not in block: continue

    instrs = esilsolver.r2pipe.cmdj("pdbj @ %d" % block["addr"])
    jump_addr = instrs[-1]["offset"]
    end = block["addr"] + block["size"]
    state = esilsolver.blank_state(block["addr"])
    state.registers["SP"] = 0x2000000 # no symbolic sp

    try:
        state = esilsolver.run(jump_addr, avoid=[end], make_calls=False)
        states = state.step() # exec the jump

        if len(states) == 1: # one state = opaque predicate
            pc = states[0].registers["PC"].as_long()
            if pc == end: # jump is never taken
                esilsolver.r2pipe.cmd("aho nop @ %d" % jump_addr)
            else: # jump is always taken
                esilsolver.r2pipe.cmd("aho jmp @ %d" % jump_addr)

        for state in states:
            pc = state.registers["PC"].as_long()
            if pc in block_dict:
                block_list.append(block_dict[pc])

    except Exception as e:
        print("error: %s" % e)

esilsolver.r2pipe.cmd("af-; af") # reanalyze

