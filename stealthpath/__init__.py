"""StealthPath — comparative attack-path planning under adaptive defender visibility.

Nothing is re-exported here on purpose. `loader_neo4j` pulls in the Neo4j driver
on import, and the whole point of the layout is that planners, the Stage 4
environment, and the tests never touch a database. Import submodules directly.
"""

__version__ = "0.1.0"
