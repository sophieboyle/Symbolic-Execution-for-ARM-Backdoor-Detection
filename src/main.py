import angr
import argparse
import sys


def arg_parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', nargs=1, 
                        help='Filename of firmware to analyse')
    args = parser.parse_args()
    return args.filename[0]


def read_bytes(filename):
    with open(filename, "rb") as f:
        bytes_str = f.read()
    return bytes_str


def access_granted(state):
    output_msg = state.posix.dumps(sys.stdout.fileno())
    if b'Access granted' in output_msg:
        return True
    else:
        return False


def abort(state):
    output_msg = state.posix.dumps(sys.stdout.fileno())
    if b'Access denied' in output_msg:
        return True
    else:
        return False


def parse_solution_dump(bytestring):
    """
    A solution must be parsed since angr cannot work with fgets or scanf.
    This is because it cannot handle the dynamic number of values readable
    from scanf or fgets. It applies constraints based on the full size of 
    the buffer instead.

    This means that the normal results returned by access_state.posix.dumps(0))
    may be filled with garbage bytes after the null character. This function
    is simply a way of formatting the output such that the garbage bytes
    are not printed.

    This could result in an extra output being emitted as an error, since a
    garbage byte may by chance be an alphanumeric character.

    Run tool at least twice to identify undefined behaviour.

    TODO: Fix this by hooking fgets() functionality in angr?
    """
    results = []
    tmp = ''
    print(bytestring)
    iterbytes = [bytestring[i:i+1] for i in range(len(bytestring))]
    for b in iterbytes:
        if b == b'\x00':
            results.append(tmp)
            tmp = ''
            continue
        try:
            tmp += b.decode('utf-8')
        except:
            pass
    return results


def main():
    filename = arg_parsing()
    project = angr.Project(filename)

    entry_state = project.factory.entry_state()
    sim = project.factory.simgr(entry_state)
    sim.explore(find=access_granted, avoid=abort)

    if sim.found:
        access_state = sim.found[0]
        print(f"Solution found: {parse_solution_dump(access_state.posix.dumps(0))}")
    else:
        print("No solution")


if __name__ == '__main__':
    main()
