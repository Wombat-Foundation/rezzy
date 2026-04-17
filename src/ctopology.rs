use alloc::vec::Vec;

/// Boolean Hypercube (H_d) for event routing.
/// In a hypercube of dimension d, there are 2^d nodes.
/// A step is valid if the XOR of two node IDs has a Hamming weight of 1.
pub struct Hypercube {
    pub dimension: usize,
    pub num_nodes: usize,
}

impl Hypercube {
    pub fn new(num_events: usize) -> Self {
        // Calculate the minimum dimension d such that 2^d >= num_events.
        let dimension = if num_events <= 1 {
            1
        } else {
            (num_events as f64).log2().ceil() as usize
        };
        let num_nodes = 1 << dimension;
        Self {
            dimension,
            num_nodes,
        }
    }

    /// Returns the shortest path between two nodes as a list of dimensions to flip.
    /// In a hypercube, this is simply the indices of the bits that differ.
    pub fn get_path(&self, u: usize, v: usize) -> Vec<usize> {
        let mut path = Vec::new();
        let diff = u ^ v;
        for i in 0..self.dimension {
            if (diff >> i) & 1 == 1 {
                path.push(i);
            }
        }
        path
    }

    /// Returns the neighbor of node `u` by flipping the bit at `dimension_idx`.
    pub fn step(&self, u: usize, dimension_idx: usize) -> usize {
        u ^ (1 << dimension_idx)
    }
}

impl Default for Hypercube {
    fn default() -> Self {
        // Default to a 10-dimensional hypercube (1024 nodes) for baseline usage.
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypercube_path() {
        let h = Hypercube::new(100);
        let u = 0b001; // 1
        let v = 0b110; // 6
        let path = h.get_path(u, v);
        // Path should flip bits at indices 0, 1, 2.
        assert_eq!(path.len(), 3);
        assert!(path.contains(&0));
        assert!(path.contains(&1));
        assert!(path.contains(&2));
    }
}
