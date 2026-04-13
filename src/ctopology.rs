use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const N: usize = 5;
pub const NUM_NODES: usize = 120; // 5!

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Permutation(pub [u8; N]);

impl Permutation {
    pub fn swap(&self, i: usize) -> Self {
        let mut next = self.0;
        next.swap(0, i);
        Permutation(next)
    }
}

pub fn generate_permutations() -> Vec<Permutation> {
    let mut perms = Vec::with_capacity(NUM_NODES);
    let current = [0, 1, 2, 3, 4];
    perms.push(Permutation(current));

    fn recurse(arr: &mut [u8; N], start: usize, perms: &mut Vec<Permutation>) {
        if start == N {
            perms.push(Permutation(*arr));
            return;
        }
        for i in start..N {
            arr.swap(start, i);
            recurse(arr, start + 1, perms);
            arr.swap(start, i);
        }
    }

    let mut all_perms = Vec::new();
    let mut arr = [0, 1, 2, 3, 4];
    recurse(&mut arr, 0, &mut all_perms);
    all_perms.sort();
    all_perms.dedup(); // recurse generates duplicates due to the naive algorithm, dedup removes them
    all_perms
}

pub struct StarGraph {
    pub nodes: Vec<Permutation>,
    pub next_step: [[u8; NUM_NODES]; NUM_NODES],
}

impl StarGraph {
    pub fn new() -> Self {
        let nodes = generate_permutations();
        assert_eq!(nodes.len(), NUM_NODES);

        let mut next_step = [[0u8; NUM_NODES]; NUM_NODES];

        for target in 0..NUM_NODES {
            let mut queue = VecDeque::new();
            let mut dist = [usize::MAX; NUM_NODES];

            queue.push_back(target);
            dist[target] = 0;

            while let Some(u) = queue.pop_front() {
                let p = &nodes[u];
                for i in 1..N {
                    let next_p = p.swap(i);
                    let v = nodes.binary_search(&next_p).unwrap();
                    if dist[v] == usize::MAX {
                        dist[v] = dist[u] + 1;
                        next_step[v][target] = i as u8;
                        queue.push_back(v);
                    }
                }
            }
        }

        Self { nodes, next_step }
    }

    pub fn get_path(&self, mut u: usize, v: usize) -> Vec<u8> {
        let mut path = Vec::new();
        while u != v {
            let step = self.next_step[u][v];
            path.push(step);
            let next_p = self.nodes[u].swap(step as usize);
            u = self.nodes.binary_search(&next_p).unwrap();
        }
        path
    }
}
