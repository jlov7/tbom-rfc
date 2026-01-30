import inspect

import scripts.ai_eval as ai_eval
import scripts.build_binaries as build_binaries
import scripts.generate_provenance as generate_provenance
import scripts.mutation_test as mutation_test
import scripts.render_demo_gif as render_demo_gif
import scripts.render_demo_video as render_demo_video
import scripts.showcase as showcase


def test_main_accepts_argv():
    for mod in [
        ai_eval,
        build_binaries,
        generate_provenance,
        mutation_test,
        render_demo_gif,
        render_demo_video,
        showcase,
    ]:
        sig = inspect.signature(mod.main)
        assert len(sig.parameters) == 1
        assert list(sig.parameters.values())[0].name == "argv"
