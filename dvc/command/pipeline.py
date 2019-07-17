from __future__ import unicode_literals

from dvc.utils.compat import str

import argparse
import os
import logging

from dvc.exceptions import DvcException
from dvc.command.base import CmdBase, fix_subparsers, append_doc_link


logger = logging.getLogger(__name__)


def show_nodes(P):
    print("@@@@@@@@@@@@@@@@@@@@@@@")
    print("@@@@ Showing nodes @@@@")
    print("@@@@@@@@@@@@@@@@@@@@@@@")
    for x, y in P.nodes(data=True):
        print("node name: {}".format(x))
        print("attr dict: {}".format(y))
    print("@@@@@@@@@@@@@@@@@@@@@@@")
    print("@@@@@@@@ DONE @@@@@@@@@")
    print("@@@@@@@@@@@@@@@@@@@@@@@")


class CmdPipelineShow(CmdBase):
    def _show(self, target, commands, outs, locked):
        import networkx
        from dvc.stage import Stage

        stage = Stage.load(self.repo, target)
        G = self.repo.graph()[0]
        stages = networkx.get_node_attributes(G, "stage")
        node = os.path.relpath(stage.path, self.repo.root_dir)
        nodes = networkx.dfs_postorder_nodes(G, node)

        if locked:
            nodes = [n for n in nodes if stages[n].locked]

        for n in nodes:
            if commands:
                logger.info(stages[n].cmd)
            elif outs:
                for out in stages[n].outs:
                    logger.info(str(out))
            else:
                logger.info(n)

    def __build_graph(self, target, commands, outs):
        import networkx
        from dvc.stage import Stage

        stage = Stage.load(self.repo, target)
        print("@@@@@@@@@@@@")
        print("@@@@@@@ build_graph: {}".format(stage))
        print("@@@@@@@@@@@@")
        node = os.path.relpath(stage.path, self.repo.root_dir)

        print("NODE IN BUILD_GRAPH: ", node)
        print("self.repo.pipelines(): ", self.repo.pipelines())
        pipelines = list(
            filter(lambda g: node in g.nodes(), self.repo.pipelines())
        )
        print("PIPELINE: ", pipelines)

        assert len(pipelines) == 1
        G = pipelines[0]
        stages = networkx.get_node_attributes(G, "stage")

        nodes = []
        print("------------ Let's talk about nodes....")
        for n in G.nodes():
            stage = stages[n]
            print("@@@ stage: {} @@@".format(stage))
            print("* type of stage: {}".format(type(stage)))
            print("* stage.cmd: {}".format(stage.cmd))
            print("* stage.outs: {}".format(stage.outs))
            print("* stage.relpath: {}".format(stage.relpath))
            if commands:
                if stage.cmd is None:
                    continue
                nodes.append(stage.cmd)
            elif outs:
                for out in stage.outs:
                    nodes.append(str(out))
            else:
                nodes.append(stage.relpath)

        print("------------ Let's talk about edges....")
        edges = []
        for e in G.edges():
            from_stage = stages[e[0]]
            to_stage = stages[e[1]]
            print("@@@ from_stage: {} @@@".format(from_stage))
            print("* to_stage: {}".format(to_stage))
            print("* type of from_stage: {}".format(type(from_stage)))
            print("* type of to_stage: {}".format(type(to_stage)))
            print("* from_stage.cmd: {}".format(from_stage.cmd))
            print("* to_stage.cmd: {}".format(to_stage.cmd))
            print("* from_stage.outs: {}".format(from_stage.outs))
            print("* to_stage.outs: {}".format(to_stage.outs))
            print("* from_stage.relpath: {}".format(from_stage.relpath))
            print("* to_stage.relpath: {}".format(to_stage.relpath))
            if commands:
                if to_stage.cmd is None:
                    continue
                edges.append((from_stage.cmd, to_stage.cmd))
            elif outs:
                for from_out in from_stage.outs:
                    for to_out in to_stage.outs:
                        edges.append((str(from_out), str(to_out)))
            else:
                edges.append((from_stage.relpath, to_stage.relpath))

        print("####" * 10)
        print("NODE: {}".format(nodes))
        print("type of nodes: {}".format(type(nodes[0])))
        print("EDGE: {}".format(edges))
        print("type of edges: {}".format(type(edges[0][0])))
        print("####" * 10)
        return nodes, edges, networkx.is_tree(G)

    def _show_ascii(self, target, commands, outs):
        from dvc.dagascii import draw

        nodes, edges, _ = self.__build_graph(target, commands, outs)

        if not nodes:
            return

        draw(nodes, edges)

    def _show_dependencies_tree(self, target, commands, outs):
        from treelib import Tree

        nodes, edges, is_tree = self.__build_graph(target, commands, outs)
        if not nodes:
            return
        if not is_tree:
            raise DvcException(
                "DAG is not a tree, can not print it in tree-structure way, "
                "please use --ascii instead"
            )

        tree = Tree()
        tree.create_node(target, target)  # Root node
        observe_list = [target]
        while len(observe_list) > 0:
            current_root = observe_list[0]
            for edge in edges:
                if edge[0] == current_root:
                    tree.create_node(edge[1], edge[1], parent=current_root)
                    observe_list.append(edge[1])
            observe_list.pop(0)
        tree.show()

    def __write_dot(self, target, commands, outs):
        from dvc.utils.compat import StringIO
        import networkx
        from networkx.drawing.nx_pydot import write_dot

        _, edges, _ = self.__build_graph(target, commands, outs)
        print("EDEGS: ", edges)
        edges = [edge[::-1] for edge in edges]
        print("EDEGS: ", edges)

        simple_g = networkx.DiGraph()
        simple_g.add_edges_from(edges)

        dot_file = StringIO()
        write_dot(simple_g, dot_file)
        logger.info(dot_file.getvalue())
        print("#" * 80)

    def run(self):
        if not self.args.targets:
            self.args.targets = self.default_targets

        for target in self.args.targets:
            try:
                if self.args.ascii:
                    self._show_ascii(
                        target, self.args.commands, self.args.outs
                    )
                elif self.args.dot:
                    self.__write_dot(
                        target, self.args.commands, self.args.outs
                    )
                elif self.args.tree:
                    self._show_dependencies_tree(
                        target, self.args.commands, self.args.outs
                    )
                else:
                    self._show(
                        target,
                        self.args.commands,
                        self.args.outs,
                        self.args.locked,
                    )
            except DvcException:
                msg = "failed to show pipeline for '{}'".format(target)
                logger.exception(msg)
                return 1
        return 0


class CmdPipelineList(CmdBase):
    def run(self):
        import networkx

        pipelines = self.repo.pipelines()
        for p in pipelines:
            stages = networkx.get_node_attributes(p, "stage")
            print("stage: ", stages)
            for stage in stages:
                print("@" * 20)
                print("@: ", stage)
                print("@: ", type(stage))
                logger.info(stage)
            if len(stages) != 0:
                logger.info("=" * 80)
        logger.info("{} pipeline(s) total".format(len(pipelines)))
        print("@" * 20)

        return 0


def add_parser(subparsers, parent_parser):
    PIPELINE_HELP = "Manage pipelines."
    pipeline_parser = subparsers.add_parser(
        "pipeline",
        parents=[parent_parser],
        description=append_doc_link(PIPELINE_HELP, "pipeline"),
        help=PIPELINE_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    pipeline_subparsers = pipeline_parser.add_subparsers(
        dest="cmd",
        help="Use dvc pipeline CMD --help for command-specific help.",
    )

    fix_subparsers(pipeline_subparsers)

    PIPELINE_SHOW_HELP = "Show pipeline."
    pipeline_show_parser = pipeline_subparsers.add_parser(
        "show",
        parents=[parent_parser],
        description=append_doc_link(PIPELINE_SHOW_HELP, "pipeline-show"),
        help=PIPELINE_SHOW_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pipeline_show_group = pipeline_show_parser.add_mutually_exclusive_group()
    pipeline_show_group.add_argument(
        "-c",
        "--commands",
        action="store_true",
        default=False,
        help="Print commands instead of paths to DVC files.",
    )
    pipeline_show_group.add_argument(
        "-o",
        "--outs",
        action="store_true",
        default=False,
        help="Print output files instead of paths to DVC files.",
    )
    pipeline_show_parser.add_argument(
        "-l",
        "--locked",
        action="store_true",
        default=False,
        help="Print locked DVC stages",
    )
    pipeline_show_parser.add_argument(
        "--ascii",
        action="store_true",
        default=False,
        help="Output DAG as ASCII.",
    )
    pipeline_show_parser.add_argument(
        "--dot",
        action="store_true",
        default=False,
        help="Print DAG with .dot format.",
    )
    pipeline_show_parser.add_argument(
        "--tree",
        action="store_true",
        default=False,
        help="Output DAG as Dependencies Tree.",
    )
    pipeline_show_parser.add_argument(
        "targets", nargs="*", help="DVC files. 'Dvcfile' by default."
    )
    pipeline_show_parser.set_defaults(func=CmdPipelineShow)

    PIPELINE_LIST_HELP = "List pipelines."
    pipeline_list_parser = pipeline_subparsers.add_parser(
        "list",
        parents=[parent_parser],
        description=append_doc_link(PIPELINE_LIST_HELP, "pipeline-list"),
        help=PIPELINE_LIST_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pipeline_list_parser.set_defaults(func=CmdPipelineList)
