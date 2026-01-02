/**
 * Test data fixtures for e2e tests
 */

const userFixtures = {
  validUser: {
    email: 'test@yaktong.com',
    password: 'password123',
    name: 'TestUser'
  },
  adminUser: {
    email: 'admin@yaktong.com',
    password: 'admin123',
    name: 'AdminUser',
    isAdmin: true
  },
  secondUser: {
    email: 'user2@yaktong.com',
    password: 'password123',
    name: 'SecondUser'
  }
};

const postFixtures = {
  validPost: {
    title: '테스트 게시글',
    content: '이것은 테스트 게시글입니다.',
    category: 'question'
  },
  anonymousPost: {
    title: '익명 게시글',
    content: '익명으로 작성된 게시글입니다.',
    category: 'anonymous',
    isAnonymous: true
  },
  discussionPost: {
    title: '토론 게시글',
    content: '토론 주제입니다.',
    category: 'discussion'
  }
};

const commentFixtures = {
  validComment: {
    content: '테스트 댓글입니다.'
  },
  replyComment: {
    content: '대댓글입니다.'
  }
};

const jobFixtures = {
  hiringJob: {
    title: '약사 구인합니다',
    type: 'hiring',
    category: '약국',
    workType: '풀타임',
    location: '서울시 강남구',
    address: '역삼동 123-45',
    workDays: '월-금',
    workHours: '09:00-18:00',
    salaryType: '월급',
    salaryMin: 400,
    salaryMax: 500,
    description: '경력 2년 이상 우대',
    phone: '010-1234-5678'
  },
  seekingJob: {
    title: '약사 구직합니다',
    type: 'seeking',
    category: '약국',
    workType: '파트타임',
    location: '서울시 서초구',
    address: '서초동 456-78',
    workDays: '토-일',
    workHours: '10:00-17:00',
    salaryType: '시급',
    salaryMin: 30,
    salaryMax: 35,
    description: '주말 근무 가능',
    phone: '010-9876-5432'
  }
};

module.exports = {
  userFixtures,
  postFixtures,
  commentFixtures,
  jobFixtures
};
